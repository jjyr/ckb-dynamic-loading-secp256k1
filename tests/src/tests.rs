use super::*;
use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::context::Context;
use ckb_tool::ckb_crypto::secp::{Generator, Privkey};
use ckb_tool::ckb_error::assert_error_eq;
use ckb_tool::ckb_hash::{blake2b_256, new_blake2b};
use ckb_tool::ckb_script::ScriptError;
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::{self, *},
    prelude::*,
    H256,
};
use rand::{thread_rng, Rng};
use std::fs;

const MAX_CYCLES: u64 = 10_000_000;

fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    const SIGNATURE_SIZE: usize = 65;

    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(SIGNATURE_SIZE, 0);
        buf.into()
    };
    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    (1..witnesses_len).for_each(|n| {
        let witness = tx.witnesses().get(n).unwrap();
        let witness_len = witness.raw_data().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness.raw_data());
    });
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(sig.serialize())).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    for i in 1..witnesses_len {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

#[test]
fn test_basic() {
    // generate key pair
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-dynamic-loading-secp256k1");
    let out_point = context.deploy_cell(contract_bin);

    let secp256k1_bin: Bytes =
        fs::read("../ckb-miscellaneous-scripts/build/secp256k1_blake2b_sighash_all_dual")
            .expect("load secp256k1")
            .into();
    let secp256k1_out_point = context.deploy_cell(secp256k1_bin);
    let secp256k1_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point)
        .build();

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, pubkey_hash.to_vec().into())
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(secp256k1_dep)
        .cell_dep(secp256k1_data_dep)
        .build();
    let tx = context.complete_tx(tx);

    // sign
    let tx = sign_tx(tx, &privkey);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_sign_with_wrong_key() {
    // generate key pair
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    let wrong_privkey = Generator::random_privkey();

    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-dynamic-loading-secp256k1");
    let out_point = context.deploy_cell(contract_bin);

    let secp256k1_bin: Bytes =
        fs::read("../ckb-miscellaneous-scripts/build/secp256k1_blake2b_sighash_all_dual")
            .expect("load secp256k1")
            .into();
    let secp256k1_out_point = context.deploy_cell(secp256k1_bin);
    let secp256k1_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point)
        .build();

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, pubkey_hash.to_vec().into())
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(secp256k1_dep)
        .cell_dep(secp256k1_data_dep)
        .build();
    let tx = context.complete_tx(tx);

    // sign
    let tx = sign_tx(tx, &wrong_privkey);

    // run
    let err = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("pass verification");
    assert_error_eq!(err, ScriptError::ValidationFailure(6),);
}

#[test]
fn test_recover_pubkey() {
    // generate key pair
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-dynamic-loading-secp256k1");
    let out_point = context.deploy_cell(contract_bin);

    let secp256k1_bin: Bytes =
        fs::read("../ckb-miscellaneous-scripts/build/secp256k1_blake2b_sighash_all_dual")
            .expect("load secp256k1")
            .into();
    let secp256k1_out_point = context.deploy_cell(secp256k1_bin);
    let secp256k1_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point)
        .build();

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, pubkey_hash.to_vec().into())
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    let mut rng = thread_rng();
    let mut message = [0u8; 32];
    rng.fill(&mut message);
    let sig = privkey.sign_recoverable(&message.into()).expect("sign");
    let witness = {
        let mut args = Vec::new();
        args.extend_from_slice(&message);
        args.extend_from_slice(&sig.serialize());
        WitnessArgs::new_builder()
            .input_type(Some(Bytes::from(args)).pack())
            .build()
            .as_bytes()
            .pack()
    };

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(secp256k1_dep)
        .cell_dep(secp256k1_data_dep)
        .witness(witness)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_recover_pubkey_with_wrong_signature() {
    // generate key pair
    let privkey = Generator::random_privkey();
    let wrong_privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-dynamic-loading-secp256k1");
    let out_point = context.deploy_cell(contract_bin);

    let secp256k1_bin: Bytes =
        fs::read("../ckb-miscellaneous-scripts/build/secp256k1_blake2b_sighash_all_dual")
            .expect("load secp256k1")
            .into();
    let secp256k1_out_point = context.deploy_cell(secp256k1_bin);
    let secp256k1_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point)
        .build();

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, pubkey_hash.to_vec().into())
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    let mut rng = thread_rng();
    let mut message = [0u8; 32];
    rng.fill(&mut message);
    let sig = wrong_privkey
        .sign_recoverable(&message.into())
        .expect("sign");
    let witness = {
        let mut args = Vec::new();
        args.extend_from_slice(&message);
        args.extend_from_slice(&sig.serialize());
        WitnessArgs::new_builder()
            .input_type(Some(Bytes::from(args)).pack())
            .build()
            .as_bytes()
            .pack()
    };

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(secp256k1_dep)
        .cell_dep(secp256k1_data_dep)
        .witness(witness)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let err = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("pass verification");
    assert_error_eq!(err, ScriptError::ValidationFailure(6),);
}
