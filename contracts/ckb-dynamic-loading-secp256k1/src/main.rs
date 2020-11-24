#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
// use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    debug, default_alloc,
    dynamic_loading::CKBDLContext,
    entry,
    error::SysError,
    high_level::{load_script, load_witness_args},
};

use blake2b_ref::{Blake2b, Blake2bBuilder};
use ckb_lib_secp256k1::LibSecp256k1;

entry!(entry);
// Alloc 4K fast HEAP + 2M HEAP to receives PrefilledData
default_alloc!(4 * 1024, 2048 * 1024, 64);

/// Program entry
fn entry() -> i8 {
    // Call main function and return error code
    match main() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

/// Error
#[repr(i8)]
enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Add customized errors here...
    Secp256k1,
    WrongPubkey,
    LoadPrefilledData,
    RecoverPubkey,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build()
}

fn test_validate_blake2b_sighash_all(
    lib: &LibSecp256k1,
    expected_pubkey_hash: &[u8],
) -> Result<(), Error> {
    let mut pubkey_hash = [0u8; 20];
    lib.validate_blake2b_sighash_all(&mut pubkey_hash)
        .map_err(|err_code| {
            debug!("secp256k1 error {}", err_code);
            Error::Secp256k1
        })?;

    // compare with expected pubkey_hash
    if &pubkey_hash[..] != expected_pubkey_hash {
        return Err(Error::WrongPubkey);
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    if args.len() != 20 {
        return Err(Error::Encoding);
    }

    let witness_args = load_witness_args(0, Source::GroupInput)?;

    // create a DL context with 128K buffer size
    let mut context = unsafe{ CKBDLContext::<[u8; 128 * 1024]>::new()};
    let lib = LibSecp256k1::load(&mut context);

    if witness_args.input_type().to_opt().is_none() {
        test_validate_blake2b_sighash_all(&lib, &args)?;
    } else {
        let witness: Bytes = witness_args
            .input_type()
            .to_opt()
            .ok_or(Error::Encoding)?
            .unpack();
        let mut message = [0u8; 32];
        let mut signature = [0u8; 65];
        let msg_len = message.len();
        let sig_len = signature.len();
        assert_eq!(witness.len(), message.len() + signature.len());
        message.copy_from_slice(&witness[..msg_len]);
        signature.copy_from_slice(&witness[msg_len..msg_len + sig_len]);
        // recover pubkey_hash
        let prefilled_data = lib.load_prefilled_data().map_err(|err| {
            debug!("load prefilled data error: {}", err);
            Error::LoadPrefilledData
        })?;
        let pubkey = lib
            .recover_pubkey(&prefilled_data, &signature, &message)
            .map_err(|err| {
                debug!("recover pubkey error: {}", err);
                Error::RecoverPubkey
            })?;
        let pubkey_hash = {
            let mut buf = [0u8; 32];
            let mut hasher = new_blake2b();
            hasher.update(pubkey.as_slice());
            hasher.finalize(&mut buf);
            buf
        };
        if &args[..] != &pubkey_hash[..20] {
            return Err(Error::WrongPubkey);
        }
    }

    Ok(())
}
