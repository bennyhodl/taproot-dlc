use crate::party_params::PartyParams;
use crate::util;
use crate::TaprootDlcError;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUALVERIFY};
use bitcoin::script::Builder;
use bitcoin::taproot::{LeafVersion, TapNodeHash};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};
use dlc::Payout;
use schnorr_fun::fun::Scalar;
use schnorr_fun::Schnorr;
use secp256k1_zkp::All;
use sha2::Sha256;
use tracing::debug;

/// Container for all DLC transactions
#[derive(Debug, Clone)]
pub struct DlcTransactions {
    pub fund: Transaction,
    pub cets: Vec<Transaction>,
    pub refund: Transaction,
    pub funding_script_pubkey: ScriptBuf,
}

/// Create the transactions for a DLC contract based on the provided parameters
pub fn create_dlc_transactions(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    payouts: &[Payout],
    refund_lock_time: u32,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    cet_lock_time: u32,
    fund_output_serial_id: u64,
) -> Result<DlcTransactions, TaprootDlcError> {
    let (fund_tx, funding_script_pubkey) = create_fund_transaction_with_fees(
        offer_params,
        accept_params,
        fee_rate_per_vb,
        fund_lock_time,
        fund_output_serial_id,
        Amount::ZERO,
    )?;

    let fund_outpoint = OutPoint {
        txid: fund_tx.compute_txid(),
        vout: util::get_output_for_script_pubkey(&fund_tx, &funding_script_pubkey)
            .expect("to find the funding script pubkey")
            .0 as u32,
    };

    let (cets, refund_tx) = create_cets_and_refund_tx(
        offer_params,
        accept_params,
        fund_outpoint,
        payouts,
        refund_lock_time,
        cet_lock_time,
        None,
    )?;

    Ok(DlcTransactions {
        fund: fund_tx,
        cets,
        refund: refund_tx,
        funding_script_pubkey,
    })
}

pub fn create_fund_transaction_with_fees(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    fund_output_serial_id: u64,
    extra_fee: Amount,
) -> Result<(Transaction, ScriptBuf), TaprootDlcError> {
    let total_collateral = offer_params.collateral + accept_params.collateral;

    let (offer_change_output, _offer_fund_fee, offer_cet_fee) =
        offer_params.get_change_output_and_fees(fee_rate_per_vb, extra_fee)?;
    let (accept_change_output, _accept_fund_fee, accept_cet_fee) =
        accept_params.get_change_output_and_fees(fee_rate_per_vb, extra_fee)?;

    // Calculate funding output amount (total collateral + fees for CETs)
    let fund_output_value = total_collateral + offer_cet_fee + accept_cet_fee + extra_fee;

    let fund_sequence = util::get_sequence(fund_lock_time);
    let (offer_tx_ins, offer_inputs_serial_ids) =
        offer_params.get_unsigned_tx_inputs_and_serial_ids(fund_sequence);
    let (accept_tx_ins, accept_inputs_serial_ids) =
        accept_params.get_unsigned_tx_inputs_and_serial_ids(fund_sequence);

    let funding_script_pubkey =
        make_funding_redeemscript(&offer_params.fund_pubkey, &accept_params.fund_pubkey);

    let fund_tx = create_funding_transaction(
        &funding_script_pubkey,
        fund_output_value,
        &offer_tx_ins,
        &offer_inputs_serial_ids,
        &accept_tx_ins,
        &accept_inputs_serial_ids,
        offer_change_output,
        offer_params.change_serial_id,
        accept_change_output,
        accept_params.change_serial_id,
        fund_output_serial_id,
        fund_lock_time,
    );

    Ok((fund_tx, funding_script_pubkey))
}

pub fn create_cets_and_refund_tx(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    prev_outpoint: OutPoint,
    payouts: &[Payout],
    refund_lock_time: u32,
    cet_lock_time: u32,
    cet_nsequence: Option<Sequence>,
) -> Result<(Vec<Transaction>, Transaction), TaprootDlcError> {
    let total_collateral = offer_params.collateral + accept_params.collateral;

    let has_proper_outcomes = payouts.iter().all(|o| {
        let total = o.offer + o.accept;
        total == total_collateral.to_sat()
    });

    if !has_proper_outcomes {
        return Err(TaprootDlcError::General("Invalid payouts".to_string()));
    }

    let cet_input = TxIn {
        previous_output: prev_outpoint,
        witness: Witness::default(),
        script_sig: ScriptBuf::default(),
        sequence: cet_nsequence.unwrap_or_else(|| util::get_sequence(cet_lock_time)),
    };

    let cets = create_cets(
        &cet_input,
        &offer_params.payout_spk,
        offer_params.payout_serial_id,
        &accept_params.payout_spk,
        accept_params.payout_serial_id,
        payouts,
        cet_lock_time,
    );

    let offer_refund_output = TxOut {
        value: offer_params.collateral,
        script_pubkey: offer_params.payout_spk.clone(),
    };

    let accept_refund_output = TxOut {
        value: accept_params.collateral,
        script_pubkey: accept_params.payout_spk.clone(),
    };

    let refund_input = TxIn {
        previous_output: prev_outpoint,
        witness: Witness::default(),
        script_sig: ScriptBuf::default(),
        sequence: util::get_sequence(refund_lock_time),
    };

    let refund_tx = create_refund_transaction(
        offer_refund_output,
        accept_refund_output,
        refund_input,
        refund_lock_time,
    );

    Ok((cets, refund_tx))
}

/// Create a contract execution transaction
pub fn create_cet(
    offer_output: TxOut,
    offer_payout_serial_id: u64,
    accept_output: TxOut,
    accept_payout_serial_id: u64,
    fund_tx_in: &TxIn,
    lock_time: u32,
) -> Transaction {
    let mut output: Vec<TxOut> = if offer_payout_serial_id < accept_payout_serial_id {
        vec![offer_output, accept_output]
    } else {
        vec![accept_output, offer_output]
    };

    output = util::discard_dust(output, Amount::from_sat(1000)); // DUST_LIMIT

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(lock_time),
        input: vec![fund_tx_in.clone()],
        output,
    }
}

/// Create a set of contract execution transaction for each provided outcome
pub fn create_cets(
    fund_tx_input: &TxIn,
    offer_payout_script_pubkey: &Script,
    offer_payout_serial_id: u64,
    accept_payout_script_pubkey: &Script,
    accept_payout_serial_id: u64,
    payouts: &[Payout],
    lock_time: u32,
) -> Vec<Transaction> {
    let mut txs: Vec<Transaction> = Vec::new();
    for payout in payouts {
        let offer_output = TxOut {
            value: Amount::from_sat(payout.offer),
            script_pubkey: offer_payout_script_pubkey.to_owned(),
        };
        let accept_output = TxOut {
            value: Amount::from_sat(payout.accept),
            script_pubkey: accept_payout_script_pubkey.to_owned(),
        };
        let tx = create_cet(
            offer_output,
            offer_payout_serial_id,
            accept_output,
            accept_payout_serial_id,
            fund_tx_input,
            lock_time,
        );

        txs.push(tx);
    }

    txs
}

/// Create a funding transaction
pub fn create_funding_transaction(
    funding_script_pubkey: &ScriptBuf,
    output_amount: Amount,
    offer_inputs: &[TxIn],
    offer_inputs_serial_ids: &[u64],
    accept_inputs: &[TxIn],
    accept_inputs_serial_ids: &[u64],
    offer_change_output: TxOut,
    offer_change_serial_id: u64,
    accept_change_output: TxOut,
    accept_change_serial_id: u64,
    fund_output_serial_id: u64,
    lock_time: u32,
) -> Transaction {
    let fund_tx_out = TxOut {
        value: output_amount,
        script_pubkey: funding_script_pubkey.clone(),
    };

    let output: Vec<TxOut> = {
        let serial_ids = vec![
            fund_output_serial_id,
            offer_change_serial_id,
            accept_change_serial_id,
        ];
        util::discard_dust(
            util::order_by_serial_ids(
                vec![fund_tx_out, offer_change_output, accept_change_output],
                &serial_ids,
            ),
            Amount::from_sat(1000), // DUST_LIMIT
        )
    };

    let input = util::order_by_serial_ids(
        [offer_inputs, accept_inputs].concat(),
        &[offer_inputs_serial_ids, accept_inputs_serial_ids].concat(),
    );

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(lock_time),
        input,
        output,
    }
}

/// Create a refund transaction
pub fn create_refund_transaction(
    offer_output: TxOut,
    accept_output: TxOut,
    funding_input: TxIn,
    locktime: u32,
) -> Transaction {
    let output = util::discard_dust(
        vec![offer_output, accept_output],
        Amount::from_sat(1000), // DUST_LIMIT
    );
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(locktime),
        input: vec![funding_input],
        output,
    }
}

/// Create the taproot funding script for the funding output
/// This creates a 2-of-2 multisig using OP_CHECKSIGADD for taproot
pub fn make_funding_redeemscript(
    offer_pubkey: &XOnlyPublicKey,
    accept_pubkey: &XOnlyPublicKey,
) -> ScriptBuf {
    let (first_pubkey, second_pubkey) = if offer_pubkey < accept_pubkey {
        (offer_pubkey, accept_pubkey)
    } else {
        (accept_pubkey, offer_pubkey)
    };

    debug!(
        "Creating funding script with pubkeys: {:?} and {:?}",
        hex::encode(first_pubkey.serialize()),
        hex::encode(second_pubkey.serialize())
    );

    let script_spend = Builder::new()
        .push_x_only_key(&first_pubkey)
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&second_pubkey)
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUALVERIFY)
        .into_script();

    let tap_tree = TapNodeHash::from_script(script_spend.as_script(), LeafVersion::TapScript);

    // Create a deterministic internal key from the two pubkeys
    let mut hasher = bitcoin::hashes::sha256::Hash::engine();
    hasher.input(&first_pubkey.serialize());
    hasher.input(&second_pubkey.serialize());
    let seed_hash = bitcoin::hashes::sha256::Hash::from_engine(hasher);
    let seed = seed_hash.as_byte_array();

    // Create schnorr context for key generation
    let nonce_gen = schnorr_fun::nonce::Synthetic::<
        Sha256,
        schnorr_fun::nonce::GlobalRng<rand::rngs::ThreadRng>,
    >::default();
    let context = Schnorr::<Sha256, _>::new(nonce_gen);
    let internal_keypair = context.new_keypair(Scalar::from_slice(&seed[..32]).unwrap());
    let internal_pubkey = internal_keypair.public_key().to_xonly_bytes();

    debug!(
        "Created funding script with tap tree: Internal pubkey: {:?}",
        hex::encode(internal_pubkey)
    );

    let secp = secp256k1_zkp::Secp256k1::<All>::new();
    ScriptBuf::new_p2tr(
        &secp,
        XOnlyPublicKey::from_slice(&internal_pubkey).unwrap(),
        Some(tap_tree),
    )
}
