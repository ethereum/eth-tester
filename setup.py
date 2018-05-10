#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import (
    setup,
    find_packages,
)


extras_require = {
    'lint': [
        'flake8>=3.5.0,<4.0.0',
    ],
    'test': [
        'pytest>=3.2.1,<4.0.0',
        'pytest-xdist>=1.22.2,<2',
        'eth-abi>=1.0.0-beta.1,<2',
        'eth-hash[pycryptodome]>=0.1.0a2,<1.0.0',
    ],
    'dev': [
        'bumpversion>=0.5.3,<1.0.0',
        'tox>=2.9.1,<3.0.0',
        'wheel>=0.30.0,<1.0.0',
    ],
    'pyethereum16': [
        "ethereum>=1.6.0,<2.0.0",
        "rlp<1",
    ],
    'pyethereum21': [
        "ethereum>=2.1.0,<2.2.0",
        "rlp<1",
    ],
    'py-evm': [
        # Pin py-evm to exact version, until it leaves alpha.
        # EVM is very high velocity and might change API at each alpha.
        "py-evm==0.2.0a17",
    ],
}

extras_require['dev'] = (
    extras_require['dev']
    + extras_require['test']
    + extras_require['lint']
)


setup(
    name='eth-tester',
    # *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
    version='0.1.0-beta.25',
    description="""Tools for testing Ethereum applications.""",
    long_description_markdown_filename='README.md',
    author='Piper Merriam',
    author_email='pipermerriam@gmail.com',
    url='https://github.com/ethereum/eth-tester',
    include_package_data=True,
    install_requires=[
        "toolz>0.8.2,<1;implementation_name=='pypy'",
        "cytoolz>=0.8.2,<1.0.0;implementation_name=='cpython'",
        "eth-utils>=1.0.1,<2.0.0",
        "rlp>=0.6.0,<2.0.0",
        "semantic_version>=2.6.0,<3.0.0",
        "eth-keys>=0.2.0-beta.3,<0.3.0",
    ],
    extras_require=extras_require,
    setup_requires=['setuptools-markdown'],
    py_modules=['eth_tester'],
    license="MIT",
    zip_safe=False,
    keywords='ethereum',
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)
