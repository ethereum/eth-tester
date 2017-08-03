#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from setuptools import (
    setup,
    find_packages,
)


DIR = os.path.dirname(os.path.abspath(__file__))


readme = open(os.path.join(DIR, 'README.md')).read()


setup(
    name='ethereum-tester',
    version='0.1.0-alpha.3',
    description="""Tools for testing Ethereum applications.""",
    long_description=readme,
    author='Piper Merriam',
    author_email='pipermerriam@gmail.com',
    url='https://github.com/pipermerriam/ethereum-tester',
    include_package_data=True,
    install_requires=[
        "cytoolz==0.8.2",
        "ethereum-utils>=0.3.1",
        "rlp==0.5.1",
        "semantic_version>=2.6.0",
    ],
    extras_require={
        'pyethereum16': [
            "ethereum>=1.6.0,<2.0.0",
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
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
