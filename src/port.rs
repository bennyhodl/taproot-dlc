use crate::util;
use crate::PartyParams;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::opcodes::all::OP_CHECKSIGADD;
use bitcoin::opcodes::all::OP_NUMEQUALVERIFY;
use bitcoin::script::Builder;
use bitcoin::taproot::LeafVersion;
use bitcoin::TapNodeHash;
use bitcoin::XOnlyPublicKey;
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, Script, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use dlc::{DlcTransactions, Error, Payout};
use rand::rngs::ThreadRng;
use schnorr_fun::fun::Scalar;
use schnorr_fun::nonce::GlobalRng;
use schnorr_fun::nonce::Synthetic;
use schnorr_fun::Schnorr;
use sha2::Sha256;

/// Minimum value that can be included in a transaction output. Under this value,
/// outputs are discarded
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#change-outputs
pub const DUST_LIMIT: Amount = Amount::from_sat(1000);

/// The transaction version
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#funding-transaction
pub const TX_VERSION: Version = Version::TWO;

/// The base weight of a fund transaction
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
pub const FUND_TX_BASE_WEIGHT: usize = 230;

/// The weight of a CET excluding payout outputs
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
pub const CET_BASE_WEIGHT: usize = 500;

/// The base weight of a transaction input computed as: (outpoint(36) + sequence(4) + scriptPubKeySize(1)) * 4
/// See: <https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees>
pub const TX_INPUT_BASE_WEIGHT: usize = 164;

/// The witness size of a P2WPKH input
/// See: <https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees>
pub const P2WPKH_WITNESS_SIZE: usize = 107;

pub const TAPROOT_WITNESS_SIZE: usize = 230;

#[macro_export]
macro_rules! checked_add {
    ($a: expr, $b: expr) => {
        $a.checked_add($b).ok_or(dlc::Error::InvalidArgument)
    };
    ($a: expr, $b: expr, $c: expr) => {
        checked_add!(checked_add!($a, $b)?, $c)
    };
    ($a: expr, $b: expr, $c: expr, $d: expr) => {
        checked_add!(checked_add!($a, $b, $c)?, $d)
    };
}

pub fn create_dlc_transactions(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    payouts: &[Payout],
    refund_lock_time: u32,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    cet_lock_time: u32,
    fund_output_serial_id: u64,
) -> Result<DlcTransactions, Error> {
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
        vout: util::get_output_for_script_pubkey(&fund_tx, &funding_script_pubkey.to_p2wsh())
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

pub(crate) fn create_fund_transaction_with_fees(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    fund_output_serial_id: u64,
    extra_fee: Amount,
) -> Result<(Transaction, ScriptBuf), Error> {
    let total_collateral = checked_add!(offer_params.collateral, accept_params.collateral)?;

    let (offer_change_output, offer_fund_fee, offer_cet_fee) =
        offer_params.get_change_output_and_fees(fee_rate_per_vb, extra_fee)?;
    let (accept_change_output, accept_fund_fee, accept_cet_fee) =
        accept_params.get_change_output_and_fees(fee_rate_per_vb, extra_fee)?;

    let fund_output_value = checked_add!(offer_params.input_amount, accept_params.input_amount)?
        - offer_change_output.value
        - accept_change_output.value
        - offer_fund_fee
        - accept_fund_fee
        - extra_fee;

    assert_eq!(
        total_collateral + offer_cet_fee + accept_cet_fee + extra_fee,
        fund_output_value
    );

    assert_eq!(
        offer_params.input_amount + accept_params.input_amount,
        fund_output_value
            + offer_change_output.value
            + accept_change_output.value
            + offer_fund_fee
            + accept_fund_fee
            + extra_fee
    );

    let fund_sequence = util::get_sequence(fund_lock_time);
    let (offer_tx_ins, offer_inputs_serial_ids) =
        offer_params.get_unsigned_tx_inputs_and_serial_ids(fund_sequence);
    let (accept_tx_ins, accept_inputs_serial_ids) =
        accept_params.get_unsigned_tx_inputs_and_serial_ids(fund_sequence);

    // TODO
    // Can do musig here
    // or the hacky check sig, add check sig, push 2, numequal
    let funding_script_pubkey =
        make_funding_redeemscript(&offer_params.fund_pubkey, &accept_params.fund_pubkey);

    let fund_tx = create_funding_transaction(
        &funding_script_pubkey,
        fund_output_value,
        &offer_tx_ins.as_slice(),
        &offer_inputs_serial_ids,
        &accept_tx_ins.as_slice(),
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

/// Create the multisig redeem script for the funding output
pub fn make_funding_redeemscript(a: &XOnlyPublicKey, b: &XOnlyPublicKey) -> ScriptBuf {
    // TODO pass the context
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let script_spend = Builder::new()
        .push_x_only_key(&first)
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&second)
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUALVERIFY)
        .into_script();

    let tap_tree = TapNodeHash::from_script(script_spend.as_script(), LeafVersion::TapScript);

    // Create an internal key using secp256kfun
    let internal_keypair =
        bitcoin::secp256k1::Keypair::new(&secp, &mut rand::thread_rng()).x_only_public_key();

    ScriptBuf::new_p2tr(&secp, internal_keypair.0, Some(tap_tree))
}

pub(crate) fn create_cets_and_refund_tx(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    prev_outpoint: OutPoint,
    payouts: &[Payout],
    refund_lock_time: u32,
    cet_lock_time: u32,
    cet_nsequence: Option<Sequence>,
) -> Result<(Vec<Transaction>, Transaction), Error> {
    let total_collateral = checked_add!(offer_params.collateral, accept_params.collateral)?;

    let has_proper_outcomes = payouts.iter().all(|o| {
        let total = checked_add!(o.offer, o.accept);
        if let Ok(total) = total {
            total == total_collateral.to_sat()
        } else {
            false
        }
    });

    if !has_proper_outcomes {
        return Err(Error::InvalidArgument);
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

    let accept_refund_ouput = TxOut {
        value: accept_params.collateral,
        script_pubkey: accept_params.payout_spk.clone(),
    };

    let refund_input = TxIn {
        previous_output: prev_outpoint,
        witness: Witness::default(),
        script_sig: ScriptBuf::default(),
        sequence: util::ENABLE_LOCKTIME,
    };

    let refund_tx = create_refund_transaction(
        offer_refund_output,
        accept_refund_ouput,
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

    output = util::discard_dust(output, DUST_LIMIT);

    Transaction {
        version: TX_VERSION,
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
            DUST_LIMIT,
        )
    };

    let input = util::order_by_serial_ids(
        [offer_inputs, accept_inputs].concat(),
        &[offer_inputs_serial_ids, accept_inputs_serial_ids].concat(),
    );

    Transaction {
        version: TX_VERSION,
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
    let output = util::discard_dust(vec![offer_output, accept_output], DUST_LIMIT);
    Transaction {
        version: TX_VERSION,
        lock_time: LockTime::from_consensus(locktime),
        input: vec![funding_input],
        output,
    }
}
