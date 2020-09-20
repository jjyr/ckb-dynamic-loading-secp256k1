# ckb-dynamic-loading-secp256k1

A contract demonstrate secp256k1 verification via dynamic loading.

This project contains two crates:

* `ckb-lib-secp256k1` - a library helps users do secp256k1 verification via dynamic loading, you can reference it in your own project.
* `ckb-dynamic-loading-secp256k1` - a contract that demonstrate how to use the `ckb-lib-secp256k1` library.

### Pre-requirement

* `capsule > 0.3.0`
* [secp256k1_blake2b_sighash_all_dual](https://github.com/nervosnetwork/ckb-miscellaneous-scripts/blob/master/c/secp256k1_blake2b_sighash_all_dual.c) which supports loaded as a shared library.

### Build contracts:

#### 1. init submodules

``` sh
git submodule init && git submodule update -r --init
```

#### 2. build the shared binary `secp256k1_blake2b_sighash_all_dual`

``` sh
cd ckb-miscellaneous-scripts && make install-tools && make all-via-docker
```

#### 3. build contract

``` sh
capsule build
```

### Run tests:

``` sh
capsule test
```
