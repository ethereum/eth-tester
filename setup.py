#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import (
    setup,
    find_packages,
)


setup(
    name='eth-tester',
    # *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
    version='0.1.0-beta.3',
    description="""Tools for testing Ethereum applications.""",
    long_description_markdown_filename='README.md',
    author='Piper Merriam',
    author_email='pipermerriam@gmail.com',
    url='https://github.com/ethereum/eth-tester',
    include_package_data=True,
    install_requires=[
        "cytoolz==0.8.2",
        "eth-utils>=0.7.1",
        "rlp>=0.5.1",
        "semantic_version>=2.6.0",
        "eth-keys>=0.1.0-beta.3",
    ],
    extras_require={
        'pyethereum16': [
            "ethereum>=1.6.0,<2.0.0",
        ],
        'py-evm': [
            "py-evm==0.2.0a5",
        ],
    },
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
    ],
)
