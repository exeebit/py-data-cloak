from setuptools import setup, find_packages

setup(
    name="py-data-cloak",
    version="0.1.1",
    description="A robust data anonymization and sanitization tool for CLI and Django.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="s4gor",
    author_email="imrans4gor@gmail.com",
    url="https://github.com/exeebit/py-data-cloak",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "Faker>=20.0.0",
        "PyYAML>=6.0",
        "click>=8.0",
    ],
    extras_require={
        "django": ["Django>=3.2"],
    },
    entry_points={
        "console_scripts": [
            "pycloak=pycloak.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
)
