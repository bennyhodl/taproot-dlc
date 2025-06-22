//! Utility functions not uniquely related to DLC

use bitcoin::{Amount, ScriptBuf, Sequence};
use bitcoin::{Script, TxOut};
use bitcoin::{WitnessProgram, WitnessVersion};
use dlc::Error;

// Setting the nSequence for every input of a transaction to this value disables
// both RBF and nLockTime usage.
pub(crate) const DISABLE_LOCKTIME: Sequence = Sequence(0xffffffff);
// Setting the nSequence for every input of a transaction to this value disables
// RBF but enables nLockTime usage.
pub(crate) const ENABLE_LOCKTIME: Sequence = Sequence(0xfffffffe);

/// The base weight of a fund transaction
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
pub const FUND_TX_BASE_WEIGHT: usize = 230;

/// The weight of a CET excluding payout outputs
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
pub const CET_BASE_WEIGHT: usize = 500;

/// The base weight of a transaction input computed as: (outpoint(36) + sequence(4) + scriptPubKeySize(1)) * 4
/// See: <https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees>
pub const TX_INPUT_BASE_WEIGHT: usize = 164;

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

/// Returns the fee for the given weight at given fee rate.
pub fn weight_to_fee(weight: usize, fee_rate: u64) -> Result<Amount, Error> {
    let amount = (f64::ceil((weight as f64) / 4.0) as u64)
        .checked_mul(fee_rate)
        .ok_or(Error::InvalidArgument)?;
    Ok(Amount::from_sat(amount))
}

/// Return the common base fee for a DLC for the given fee rate.
// pub fn get_common_fee(fee_rate: u64) -> Result<Amount, Error> {
//     let base_weight = FUND_TX_BASE_WEIGHT + CET_BASE_WEIGHT;
//     weight_to_fee(base_weight, fee_rate)
// }

/// Transforms a redeem script for a p2tr output to a script signature.
pub(crate) fn redeem_script_to_script_sig(redeem: &Script) -> ScriptBuf {
    match redeem.len() {
        0 => ScriptBuf::new(),
        _ => {
            let bytes = redeem.as_bytes();
            ScriptBuf::new_witness_program(&WitnessProgram::new(WitnessVersion::V1, bytes).unwrap())
        }
    }
}

/// Sorts the given inputs in following the order of the ids.
pub(crate) fn order_by_serial_ids<T>(inputs: Vec<T>, ids: &[u64]) -> Vec<T> {
    debug_assert!(inputs.len() == ids.len());
    let mut combined: Vec<(&u64, T)> = ids.iter().zip(inputs).collect();
    combined.sort_by(|a, b| a.0.partial_cmp(b.0).unwrap());
    combined.into_iter().map(|x| x.1).collect()
}

/// Filters the outputs that have a value lower than the given `dust_limit`.
pub(crate) fn discard_dust(txs: Vec<TxOut>, dust_limit: Amount) -> Vec<TxOut> {
    txs.into_iter().filter(|x| x.value >= dust_limit).collect()
}

pub(crate) fn get_sequence(lock_time: u32) -> Sequence {
    if lock_time == 0 {
        DISABLE_LOCKTIME
    } else {
        ENABLE_LOCKTIME
    }
}
