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
        'pytest>=4.4.0,<5.0.0',
        'pytest-xdist>=1.22.2,<2',
        'eth-hash[pycryptodome]>=0.1.4,<1.0.0',
    ],
    'dev': [
        'bumpversion>=0.5.3,<1.0.0',
        'tox>=2.9.1,<3.0.0',
        'wheel>=0.30.0,<1.0.0',
    ],
    'py-evm': [
        # Pin py-evm to exact version, until it leaves alpha.
        # EVM is very high velocity and might change API at each alpha.
        "py-evm==0.3.0a15",
        "eth-hash[pysha3]>=0.1.4,<1.0.0;implementation_name=='cpython'",
        "eth-hash[pycryptodome]>=0.1.4,<1.0.0;implementation_name=='pypy'",
    ],
}

extras_require['dev'] = (
    extras_require['dev'] +
    extras_require['test'] +
    extras_require['py-evm'] +
    extras_require['lint']
)
# convenience in case someone leaves out the `-`
extras_require['pyevm'] = extras_require['py-evm']

with open('./README.md') as readme:
    long_description = readme.read()

setup(
    name='eth-tester',
    # *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
    version='0.5.0-beta.1',
    description="""Tools for testing Ethereum applications.""",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Piper Merriam',
    author_email='pipermerriam@gmail.com',
    url='https://github.com/ethereum/eth-tester',
    include_package_data=True,
    install_requires=[
        "eth-abi>=2.0.0b4,<3.0.0",
        "eth-keys>=0.2.1,<0.4.0",
        "eth-utils>=1.4.1,<2.0.0",
        "rlp>=1.1.0,<2.0.0",
        "semantic_version>=2.6.0,<3.0.0",
    ],
    extras_require=extras_require,
    python_requires='>=3.6.8,<4',
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
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
