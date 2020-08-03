# ckb-dynamic-loading-secp256k1

A contract that do secp256k1 verification via dynamic loading.

### Pre-requirement

* `ckb-std > 0.6.0` which supports dynamic loading.
* [secp256k1_blake2b_sighash_all_dual](https://github.com/nervosnetwork/ckb-miscellaneous-scripts/blob/master/c/secp256k1_blake2b_sighash_all_dual.c) which supports loaded as a shared library.

### Build contracts:

#### 1. init submodules

``` sh
git submodule init && git submodule update -r
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
