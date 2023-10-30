Eth Tester Changelog
====================

.. towncrier release notes start

eth-tester v0.10.0-beta.1 (2023-10-30)
--------------------------------------

Breaking Changes
~~~~~~~~~~~~~~~~

- Drop python 3.7 support (`#273 <https://github.com/ethereum/eth-tester/issues/273>`__)


Features
~~~~~~~~

- Add support for ``eth_feeHistory`` for ``PyEVMBackend`` via ``get_fee_history()`` method. (`#258 <https://github.com/ethereum/eth-tester/issues/258>`__)
- Add python 3.11 support (`#273 <https://github.com/ethereum/eth-tester/issues/273>`__)


Internal Changes - for eth-tester Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Merge in updates from the python project template (`#273 <https://github.com/ethereum/eth-tester/issues/273>`__)


eth-tester v0.9.1-beta.1 (2023-07-26)
-------------------------------------

Features
~~~~~~~~

- Allow filter topics to be passed as `bytes` in addition to `hex` values. (#185 https://github.com/ethereum/eth-tester/issues/185)
- Add mnemonic hd_path parameter to create custom accounts in pyevm backend. (#259 https://github.com/ethereum/eth-tester/issues/259)
- Add support for ``eth_getStorageAt`` for ``PyEVMBackend`` via ``get_storage_at()`` method. (#264 https://github.com/ethereum/eth-tester/issues/264)


Bugfixes
~~~~~~~~

- Do not return a contract address if the contract deployment transaction has failed (receipt "status" is 0). (#261 https://github.com/ethereum/eth-tester/issues/261)


Internal Changes - for eth-tester Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Bump ``py-evm`` dependency to ``v0.7.0-a.4`` (#268 https://github.com/ethereum/eth-tester/issues/268)


eth-tester v0.9.0-beta.1 (2023-05-12)
-------------------------------------

Features
~~~~~~~~

- Add support for ``Shanghai`` network upgrade and add method on ``PyEVMBackend`` to be able to initiate withdrawals. (#257 https://github.com/ethereum/eth-tester/issues/257)


Internal Changes - for eth-tester Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Update CircleCI common steps to update ``pip`` and install ``tox`` dependency at the sys level, not ``--user``. (#255 https://github.com/ethereum/eth-tester/issues/255)


eth-tester v0.8.0-beta.3 (2022-12-16)
-------------------------------------

Miscellaneous changes
~~~~~~~~~~~~~~~~~~~~~

- #251 https://github.com/ethereum/eth-tester/issues/251


eth-tester v0.8.0-beta.2 (2022-12-16)
------------------------------

Miscellaneous changes
~~~~~~~~~~~~~~~~~~~~~

- #250 https://github.com/ethereum/eth-tester/issues/250


eth-tester v0.8.0-beta.1 (2022-11-21)
-------------------------------------

Internal Changes - for eth-tester Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Update all references for deprecated ``eth_abi.encode_abi`` to ``eth_abi.encode``. (#242 https://github.com/ethereum/eth-tester/issues/242)
- Update instances of ``decode_abi()`` and ``decode_single()`` to ``abi.decode()`` in preparation for the relevant ``eth-abi`` changes. (#244 https://github.com/ethereum/eth-tester/issues/244)


Miscellaneous changes
~~~~~~~~~~~~~~~~~~~~~

- #239 https://github.com/ethereum/eth-tester/issues/239


Breaking changes
~~~~~~~~~~~~~~~~

- Support for py-evm ``paris`` hard fork. Refactor the coinbase account ``miner`` -> ``coinbase``. Support for ``safe`` and ``finalized`` block identifiers. (#245 https://github.com/ethereum/eth-tester/issues/245)
- Pending block may only be retrieved via ``"pending"`` block identifier and not directly by number since it has not yet been "mined" / added to the chain. (#249 https://github.com/ethereum/eth-tester/issues/249)


eth-tester v0.7.0-beta.1 (2022-08-25)
-------------------------------------

Misc
~~~~

- https://github.com/ethereum/eth-tester/issues/230


eth-tester v0.6.0-beta.6 (2022-01-26)
-------------------------------------

Bugfixes
~~~~~~~~

- Revert upstream dependency requirements so they can be pulled into the
  current web3.py (v5) (https://github.com/ethereum/eth-tester/issues/232)


eth-tester v0.6.0-beta.5 (2022-01-20)
-------------------------------------

Features
~~~~~~~~

- Add `to`, `from`, and `status` to transaction receipts
  (https://github.com/ethereum/eth-tester/issues/228)
- Add support for Python 3.10
  (https://github.com/ethereum/eth-tester/issues/231)


Deprecations and Removals
~~~~~~~~~~~~~~~~~~~~~~~~~

- Drop support for Python 3.6
  (https://github.com/ethereum/eth-tester/issues/231)


Misc
~~~~

- https://github.com/ethereum/eth-tester/issues/230


eth-tester v0.6.0-beta.4 (2021-11-19)
-------------------------------------

Bugfixes
~~~~~~~~

- Support pre-London blocks with missing base fee by setting the
  ``base_fee_per_gas`` value to ``None`` during block validation and popping it
  back out during block normalization
  (https://github.com/ethereum/eth-tester/issues/227)


Improved Documentation
~~~~~~~~~~~~~~~~~~~~~~

- Update README to include current release note instructions.
  (https://github.com/ethereum/eth-tester/issues/226)


eth-tester v0.6.0-beta.3 (2021-11-18)
-------------------------------------

Bugfixes
~~~~~~~~

- Only add `base_fee_per_gas` to block serializer after London
  (https://github.com/ethereum/eth-tester/issues/218)
- Return a `v` field with `y_parity` value, rather than a `y_parity` field, for
  typed transactions. (https://github.com/ethereum/eth-tester/issues/224)


Misc
~~~~

- https://github.com/ethereum/eth-tester/issues/213


eth-tester v0.6.0-beta.2
------------------------

Released 2021-11-10

- Features

  - Allow `nonce` parameter for inbound transactions to `eth_call` and `eth_estimateGas`
  - Increase default block gas limit to gas limit at London hard fork (30029122)

- Misc

  - Reference new public method generate_genesis_state instead of
    protected version in README
	- Created better test for gas estimate with block identifiers
  - Update README.md with the link to the Circle CI build status

eth-tester v0.6.0-beta.1
------------------------

Released 2021-11-04

- Breaking Changes
  - London support (https://github.com/ethereum/eth-tester/pull/206)
    - Upgrade py-evm to v0.5.0-alpha.1 for London support
    - Default to London

- Features

  - London support (https://github.com/ethereum/eth-tester/pull/206)
    - Support access list transactions and dynamic fee transactions
    - Transaction param support for `access_list`, `type`, `max_fee_per_gas`, `max_priority_fee_per_gas`
    - Transaction receipt param support for `type` and `effective_gas_price`
    - Block param support for `base_fee_per_gas`
  - Support for custom mnemonic when initializing the Backend for EthTester
  - New public, pass-through methods PyEVMBackend.generate_genesis_params and
    PyEVMBackend.generate_genesis_state

- Misc

  - Adjust wording in README regarding genesis parameters

eth-tester v0.5.0-beta.4
------------------------

Released 2021-04-12

- Features

  - Upgrade py-evm to v0.4.0-alpha.4 for Python 3.9 support
	https://github.com/ethereum/eth-tester/pull/205
  - Upgrade py-evm to v0.4.0-alpha.3, for Berlin support
    Default to Berlin
    https://github.com/ethereum/eth-tester/pull/204


eth-tester v0.5.0-beta.2
------------------------

Released 2020-08-31

- Features

  - Officially support py3.8
    https://github.com/ethereum/eth-tester/pull/195

- Performance

  - Upgrade pyrlp to v2-alpha1, with faster encoding/decoding
    https://github.com/ethereum/eth-tester/pull/195

- Misc

  - Pypy support completely dropped (it was never officially added,
    only some pieces were tested, in hopes of eventually supporting)
    https://github.com/ethereum/eth-tester/pull/195
  - Upgrade to pyevm v0.3.0-alpha.19
    https://github.com/ethereum/eth-tester/pull/196

eth-tester v0.5.0-beta.1
------------------------

Released 2020-06-01

- Breaking changes

  - Make gas limit constant for py-evm backend
    https://github.com/ethereum/eth-tester/pull/192

- Features

  - Add support for gas estimate block identifiers
    https://github.com/ethereum/eth-tester/pull/189
  - Add support for custom virtual machine fork schedule in PyEVMBackend
    https://github.com/ethereum/eth-tester/pull/191


eth-tester v0.4.0-beta.2
------------------------

- Misc

  - Upgrade eth-keys to allow 0.3.* versions
  - Upgrade py-evm to v0.3.0-alpha.15, which allows the eth-keys upgrade


eth-tester v0.4.0-beta.1
------------------------

- Misc

  - Upgrade to py-evm v0.3.0-b11
    https://github.com/ethereum/eth-tester/pull/172


eth-tester v0.3.0-beta.1
------------------------

- Breaking changes

  - Default to IstanbulVM
    https://github.com/ethereum/eth-tester/pull/169

- Misc

  - Upgrade to py-evm v0.3.0-b7
    https://github.com/ethereum/eth-tester/pull/166
  - Upgrade to py-evm v0.3.0-b8
    https://github.com/ethereum/eth-tester/pull/171

eth-tester v0.2.0-beta.2
------------------------

Released June 19, 2019

- Misc

  - Upgrade to py-evm v0.3.0-b1
    https://github.com/ethereum/eth-tester/pull/164

eth-tester v0.2.0-beta.1
------------------------

Released June 13, 2019

- Breaking changes

  - Drop Python 3.5
    https://github.com/ethereum/eth-tester/pull/160
  - Upgrade to Py-EVM 0.2.0-a43
    https://github.com/ethereum/eth-tester/pull/162


eth-tester v0.1.0-beta.39
-------------------------

Released April 12, 2019

- Misc

  - Update default VM rules to Constantinople
    https://github.com/ethereum/eth-tester/pull/153

eth-tester v0.1.0-beta.38
-------------------------

Released April 10, 2019

- Misc

  - Update PyEVM and Pytest Dependencies
    https://github.com/ethereum/eth-tester/pull/152

eth-tester 0.1.0-beta.37
------------------------

Released Jan 22, 2019

- Misc

  - Make PyEVMBackend subclass of BaseChainBackend
    https://github.com/ethereum/eth-tester/pull/150

eth-tester v0.1.0-beta.36
-------------------------

Released Jan 10, 2019

- Misc

  - Upgrade eth-keys and rlp
    https://github.com/ethereum/eth-tester/pull/146

eth-tester v0.1.0-beta.35
-------------------------

Released Jan 9, 2019

- Misc

  - Upgrade py-evm to 0.2.0a38
    https://github.com/ethereum/eth-tester/pull/143
  - Readme fixups
    https://github.com/ethereum/eth-tester/pull/144
  - Remove dead `formatting` module, replace with `eth-utils` utilities
    https://github.com/ethereum/eth-tester/pull/145

eth-tester v0.1.0-beta.34
-------------------------

Released Dec 20, 2018

- Breaking changes

  - Update eth-abi from v1 to v2
    https://github.com/ethereum/eth-tester/pull/141

- Misc

  - Improve error message when trying to sign with an unknown address
    https://github.com/ethereum/eth-tester/pull/140
  - Add custom genesis examples to docs
    https://github.com/ethereum/eth-tester/pull/136
  - Steps toward pypy support, by using eth_utils.toolz
    https://github.com/ethereum/eth-tester/pull/138
  - Remove duplicate generate_contract_address, drop custom secp256k1 and jacobian utilities
    https://github.com/ethereum/eth-tester/pull/137
  - Upgrade eth-utils (and eth-abi)
    https://github.com/ethereum/eth-tester/pull/141

eth-tester v0.1.0-beta.33
-------------------------

Released Oct 4, 2018

- Add some low-level internal tools for setting genesis parameters (API subject to change)
  https://github.com/ethereum/eth-tester/pull/123
- Upgrade py-evm to alpha 33 https://github.com/ethereum/eth-tester/pull/134
- Misc testing & dependency fixes https://github.com/ethereum/eth-tester/pull/127

eth-tester v0.1.0
-----------------

Initial release
