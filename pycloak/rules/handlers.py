from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import random
import re
import string
from typing import Any

from ..exceptions import InvalidRuleError
from .base import Rule, RuleContext


# Module-level registry. Populated by @register_rule.
RULES: list[type[Rule]] = []


def register_rule(cls: type[Rule]) -> type[Rule]:
    RULES.append(cls)
    return cls


# --- Identity / replacement rules ---------------------------------------------

@register_rule
class FakerRule(Rule):
    """faker:<provider>[:<arg>...] -> result of fake.<provider>(*args)."""

    def __init__(self, provider: str, args: tuple[str, ...] = ()):
        self.provider = provider
        self.args = args
        self.spec = f"faker:{provider}" + ("".join(f":{a}" for a in args) if args else "")

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec.startswith("faker:")

    @classmethod
    def parse(cls, spec: str) -> "FakerRule":
        parts = spec.split(":")
        provider = parts[1]
        args = tuple(parts[2:])
        if not provider:
            raise InvalidRuleError(f"faker rule needs a provider: {spec!r}")
        return cls(provider, args)

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        try:
            method = getattr(ctx.faker, self.provider)
        except AttributeError as e:
            raise InvalidRuleError(f"Unknown Faker provider: {self.provider!r}") from e
        args = [_coerce_arg(a) for a in self.args]
        return method(*args) if args else method()


def _coerce_arg(s: str):
    """Best-effort type coercion for faker args from YAML strings."""
    if s == "true":
        return True
    if s == "false":
        return False
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        return s


@register_rule
class FixedRule(Rule):
    """fixed:<value> -> always replace with <value>."""

    def __init__(self, value: str):
        self.value = value
        self.spec = f"fixed:{value}"

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec.startswith("fixed:")

    @classmethod
    def parse(cls, spec: str) -> "FixedRule":
        return cls(spec.split(":", 1)[1])

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        return self.value


@register_rule
class ClearRule(Rule):
    """clear -> None."""

    def __init__(self):
        self.spec = "clear"

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec == "clear"

    @classmethod
    def parse(cls, spec: str) -> "ClearRule":
        return cls()

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        return None


@register_rule
class RedactRule(Rule):
    """redact[:<placeholder>] -> '[REDACTED]' or custom placeholder."""

    def __init__(self, placeholder: str = "[REDACTED]"):
        self.placeholder = placeholder
        self.spec = "redact" if placeholder == "[REDACTED]" else f"redact:{placeholder}"

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec == "redact" or spec.startswith("redact:")

    @classmethod
    def parse(cls, spec: str) -> "RedactRule":
        if spec == "redact":
            return cls()
        return cls(spec.split(":", 1)[1])

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        return self.placeholder


# --- Text transforms ----------------------------------------------------------

@register_rule
class MaskAllButLastRule(Rule):
    """mask_all_but_last_<n> -> replace all but trailing N chars with '*'."""

    _re = re.compile(r"^mask_all_but_last_(\d+)$")

    def __init__(self, n: int):
        self.n = n
        self.spec = f"mask_all_but_last_{n}"

    @classmethod
    def matches(cls, spec: str) -> bool:
        return bool(cls._re.match(spec))

    @classmethod
    def parse(cls, spec: str) -> "MaskAllButLastRule":
        m = cls._re.match(spec)
        if not m:
            raise InvalidRuleError(spec)
        return cls(int(m.group(1)))

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        s = str(value)
        if len(s) <= self.n:
            return s
        return "*" * (len(s) - self.n) + s[-self.n:]


@register_rule
class PartialRule(Rule):
    """partial:<keep_start>:<keep_end>[:<mask_char>] -> keep first N and last M chars."""

    def __init__(self, keep_start: int, keep_end: int, mask_char: str = "*"):
        self.keep_start = keep_start
        self.keep_end = keep_end
        self.mask_char = mask_char
        self.spec = f"partial:{keep_start}:{keep_end}" + (f":{mask_char}" if mask_char != "*" else "")

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec.startswith("partial:")

    @classmethod
    def parse(cls, spec: str) -> "PartialRule":
        parts = spec.split(":")
        if len(parts) < 3:
            raise InvalidRuleError(f"partial needs keep_start and keep_end: {spec!r}")
        try:
            start = int(parts[1])
            end = int(parts[2])
        except ValueError as e:
            raise InvalidRuleError(f"partial start/end must be integers: {spec!r}") from e
        mask_char = parts[3] if len(parts) > 3 else "*"
        return cls(start, end, mask_char)

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        s = str(value)
        if len(s) <= self.keep_start + self.keep_end:
            return s
        middle_len = len(s) - self.keep_start - self.keep_end
        return s[: self.keep_start] + (self.mask_char * middle_len) + (s[-self.keep_end :] if self.keep_end else "")


@register_rule
class FormatPreserveRule(Rule):
    """format_preserve[:luhn] -> preserve char classes (digits, upper, lower).

    With :luhn, the digit-only subsequence is rewritten to be Luhn-valid
    (useful for credit cards). Separators / non-alphanumeric chars are kept.
    """

    def __init__(self, mode: str = ""):
        self.mode = mode
        self.spec = "format_preserve" + (f":{mode}" if mode else "")

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec == "format_preserve" or spec.startswith("format_preserve:")

    @classmethod
    def parse(cls, spec: str) -> "FormatPreserveRule":
        mode = spec.split(":", 1)[1] if ":" in spec else ""
        return cls(mode)

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        s = str(value)
        out_chars: list[str] = []
        digit_positions: list[int] = []
        for i, ch in enumerate(s):
            if ch.isdigit():
                out_chars.append(str(ctx.rng.randint(0, 9)))
                digit_positions.append(i)
            elif ch.isupper():
                out_chars.append(ctx.rng.choice(string.ascii_uppercase))
            elif ch.islower():
                out_chars.append(ctx.rng.choice(string.ascii_lowercase))
            else:
                out_chars.append(ch)

        if self.mode == "luhn" and len(digit_positions) >= 2:
            # Recompute the last digit so the whole digit sequence is Luhn-valid.
            digits = [int(out_chars[p]) for p in digit_positions]
            check = _luhn_check_digit(digits[:-1])
            out_chars[digit_positions[-1]] = str(check)

        return "".join(out_chars)


def _luhn_check_digit(digits_without_check: list[int]) -> int:
    total = 0
    # Iterate right-to-left, doubling every second digit starting from the rightmost.
    for i, d in enumerate(reversed(digits_without_check)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


# --- Hash / pseudonymization --------------------------------------------------

@register_rule
class HashRule(Rule):
    """hash[:<algo>[:<salt>]] -> deterministic hex digest.

    Examples: hash, hash:sha256, hash:sha256:mysalt
    """

    def __init__(self, algo: str = "sha256", salt: str = ""):
        if algo not in hashlib.algorithms_guaranteed:
            raise InvalidRuleError(f"Unknown hash algo: {algo!r}")
        self.algo = algo
        self.salt = salt
        self.spec = f"hash:{algo}" + (f":{salt}" if salt else "")

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec == "hash" or spec.startswith("hash:")

    @classmethod
    def parse(cls, spec: str) -> "HashRule":
        parts = spec.split(":", 2)
        algo = parts[1] if len(parts) > 1 and parts[1] else "sha256"
        salt = parts[2] if len(parts) > 2 else ""
        return cls(algo, salt)

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        h = hashlib.new(self.algo)
        h.update(self.salt.encode("utf-8"))
        h.update(str(value).encode("utf-8"))
        return h.hexdigest()


# --- Numeric / date transforms ------------------------------------------------

@register_rule
class NoiseRule(Rule):
    """noise:<sigma> -> add Gaussian noise (additive) to a numeric value.

    Output type matches input (int input rounds; float input stays float).
    Use a fractional sigma like noise:0.5 for sub-unit jitter.
    """

    def __init__(self, sigma: float):
        self.sigma = sigma
        self.spec = f"noise:{sigma}"

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec.startswith("noise:")

    @classmethod
    def parse(cls, spec: str) -> "NoiseRule":
        try:
            sigma = float(spec.split(":", 1)[1])
        except ValueError as e:
            raise InvalidRuleError(f"noise sigma must be a number: {spec!r}") from e
        return cls(sigma)

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        try:
            num = float(value)
        except (TypeError, ValueError):
            return value
        noisy = num + ctx.rng.gauss(0, self.sigma)
        if isinstance(value, int):
            return int(round(noisy))
        return noisy


@register_rule
class ShiftDateRule(Rule):
    """shift_date:<max_days> -> shift a date randomly within ±max_days.

    Accepts ISO 8601 strings (date or datetime), datetime.date, and
    datetime.datetime. Returns the same type as the input.
    """

    def __init__(self, max_days: int):
        self.max_days = max_days
        self.spec = f"shift_date:{max_days}"

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec.startswith("shift_date:")

    @classmethod
    def parse(cls, spec: str) -> "ShiftDateRule":
        raw = spec.split(":", 1)[1].lstrip("±+")
        try:
            max_days = int(raw)
        except ValueError as e:
            raise InvalidRuleError(f"shift_date needs an integer day count: {spec!r}") from e
        if max_days <= 0:
            raise InvalidRuleError(f"shift_date day count must be positive: {spec!r}")
        return cls(max_days)

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        delta = dt.timedelta(days=ctx.rng.randint(-self.max_days, self.max_days))
        if isinstance(value, dt.datetime):
            return value + delta
        if isinstance(value, dt.date):
            return value + delta
        if isinstance(value, str):
            parsed = _parse_iso(value)
            if parsed is None:
                return value
            shifted = parsed + delta
            if isinstance(parsed, dt.datetime):
                return shifted.isoformat()
            return shifted.isoformat()
        return value


def _parse_iso(s: str):
    try:
        if "T" in s or " " in s and ":" in s:
            return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.date.fromisoformat(s)
    except ValueError:
        return None


# --- Custom callable ----------------------------------------------------------

@register_rule
class CustomRule(Rule):
    """custom:<module.path>:<function_name> -> call user-defined function.

    The function is called as `fn(value, ctx)` and must return the masked value.
    """

    def __init__(self, dotted_path: str, func_name: str):
        self.dotted_path = dotted_path
        self.func_name = func_name
        self.spec = f"custom:{dotted_path}:{func_name}"
        self._fn = None  # lazy import

    @classmethod
    def matches(cls, spec: str) -> bool:
        return spec.startswith("custom:")

    @classmethod
    def parse(cls, spec: str) -> "CustomRule":
        # custom:<dotted.module>:<function>
        rest = spec.split(":", 1)[1]
        if ":" not in rest:
            raise InvalidRuleError(f"custom needs module:function form: {spec!r}")
        dotted, func = rest.rsplit(":", 1)
        if not dotted or not func:
            raise InvalidRuleError(f"custom needs module:function form: {spec!r}")
        return cls(dotted, func)

    def _resolve(self):
        if self._fn is None:
            module = importlib.import_module(self.dotted_path)
            try:
                self._fn = getattr(module, self.func_name)
            except AttributeError as e:
                raise InvalidRuleError(
                    f"Module {self.dotted_path!r} has no function {self.func_name!r}"
                ) from e
        return self._fn

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        return self._resolve()(value, ctx)
