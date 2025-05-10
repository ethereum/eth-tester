#!/usr/bin/env python
from setuptools import (
    find_packages,
    setup,
)

extras_require = {
    "dev": [
        "build>=0.9.0",
        "bump_my_version>=0.19.0",
        "ipython",
        "pre-commit>=3.4.0",
        "tox>=4.0.0",
        "twine",
        "wheel",
    ],
    "docs": [
        "towncrier>=24,<25",
    ],
    "test": [
        "pytest>=7.0.0",
        "pytest-xdist>=2.0.0,<3",
        "eth-hash[pycryptodome]>=0.1.4,<1.0.0",
    ],
    "py-evm": [
        # Pin py-evm to a minor version range to ensure compatibility with the current
        # implemented EVM version.
        "py-evm>=0.10.0b0,<0.11.0b0",
        "eth-hash[pysha3]>=0.1.4,<1.0.0;implementation_name=='cpython'",
        "eth-hash[pycryptodome]>=0.1.4,<1.0.0;implementation_name=='pypy'",
    ],
    "eels": [
        "ethereum-execution==1.17.0rc6.dev1",
    ],
}

extras_require["dev"] = (
    extras_require["dev"]
    + extras_require["docs"]
    + extras_require["test"]
    + extras_require["py-evm"]
    + extras_require["eels"]
)
# convenience in case someone leaves out the `-`
extras_require["pyevm"] = extras_require["py-evm"]

with open("./README.md") as readme:
    long_description = readme.read()

setup(
    name="eth-tester",
    # *IMPORTANT*: Don't manually change the version here. See `Release setup` in the `README`.
    version="0.12.1-beta.1",
    description="""eth-tester: Tools for testing Ethereum applications.""",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="The Ethereum Foundation",
    author_email="snakecharmers@ethereum.org",
    url="https://github.com/ethereum/eth-tester",
    include_package_data=True,
    install_requires=[
        "eth-abi>=3.0.1",
        "eth-account>=0.12.3",
        "eth-keys>=0.4.0",
        "eth-utils>=2.0.0",
        "rlp>=3.0.0",
        "semantic_version>=2.6.0",
    ],
    extras_require=extras_require,
    python_requires=">=3.8,<4",
    py_modules=["eth_tester"],
    license="MIT",
    zip_safe=False,
    keywords="ethereum",
    packages=find_packages(exclude=["scripts", "scripts.*", "tests", "tests.*"]),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
)
