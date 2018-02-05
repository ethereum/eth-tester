#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import (
    setup,
    find_packages,
)


setup(
    name='eth-tester',
    # *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
    version='0.1.0-beta.16',
    description="""Tools for testing Ethereum applications.""",
    long_description_markdown_filename='README.md',
    author='Piper Merriam',
    author_email='pipermerriam@gmail.com',
    url='https://github.com/ethereum/eth-tester',
    include_package_data=True,
    install_requires=[
        "cytoolz>=0.9.0,<1.0.0",
        "eth-utils>=1.0.0-beta.1,<2.0.0",
        "rlp>=0.6.0,<1.0.0",
        "semantic_version>=2.6.0,<3.0.0",
        "eth-keys>=0.2.0b1,<0.3.0",
    ],
    extras_require={
        'pyethereum16': [
            "ethereum>=1.6.0,<2.0.0",
        ],
        'pyethereum21': [
            "ethereum>=2.1.0,<2.2.0",
        ],
        'py-evm': [
            "py-evm==0.2.0a10",  # evm is very high velocity and might change API at each alpha
        ],
    },
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
