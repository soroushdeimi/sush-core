#!/usr/bin/env python3
"""
Setup script for SpectralFlow
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="spectralflow",
    version="1.0.0",
    author="SpectralFlow Development Team",
    description="Quantum-resistant censorship circumvention system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "spectralflow=spectralflow_cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "spectralflow": ["config/*.conf"],
    },
    project_urls={
        "Bug Reports": "https://github.com/yourusername/spectralflow/issues",
        "Source": "https://github.com/yourusername/spectralflow",
        "Documentation": "https://github.com/yourusername/spectralflow/blob/main/docs/",
    },
)
