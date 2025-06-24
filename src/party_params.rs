use std::ops::Deref;

use crate::checked_add;
use crate::get_new_serial_id;
use crate::util;
use crate::FundingInput;
use crate::TaprootDlcError;
use bitcoin::consensus::Encodable;
use bitcoin::Sequence;
use bitcoin::TxIn;
use bitcoin::Witness;
use bitcoin::{Amount, ScriptBuf, TxOut, XOnlyPublicKey};
use ddk_manager::Blockchain;
use ddk_manager::Wallet;
use dlc::TxInputInfo;
use tracing::debug;
use tracing::error;

#[derive(Debug)]
pub struct PartyParams {
    pub fund_pubkey: XOnlyPublicKey,
    // The payout script for receiving the payout
    pub payout_spk: ScriptBuf,
    // The change script for receiving the change of a funding transaction
    pub change_spk: ScriptBuf,
    // The serial id of the change output
    pub change_serial_id: u64,
    // The serial id of the payout output
    pub payout_serial_id: u64,
    // The collateral amount required for the contract
    pub collateral: Amount,
    // The funding transaction info for the contract
    pub funding_tx_info: Vec<TxInputInfo>,
    // The input amount for the contract
    pub input_amount: Amount,
}

impl PartyParams {
    /// Returns the change output for a single party as well as the fees that
    /// they are required to pay for the fund transaction and the cet or refund transaction.
    /// The change output value already accounts for the required fees.
    /// If input amount (sum of all input values) is lower than the sum of the collateral
    /// plus the required fees, an error is returned.
    pub fn get_change_output_and_fees(
        &self,
        fee_rate_per_vb: u64,
        extra_fee: Amount,
    ) -> Result<(TxOut, Amount, Amount), TaprootDlcError> {
        let mut inputs_weight: usize = 0;

        for w in &self.funding_tx_info {
            let script_weight = util::redeem_script_to_script_sig(&w.redeem_script)
                .len()
                .checked_mul(4)
                .ok_or_else(|| {
                    error!("Invalid redeem script");
                    TaprootDlcError::General("Invalid redeem script".to_string())
                })?;

            inputs_weight = checked_add!(
                inputs_weight,
                util::TX_INPUT_BASE_WEIGHT,
                script_weight,
                w.max_witness_len
            )?;
        }

        // Value size + script length var_int + ouput script pubkey size
        let change_size = self.change_spk.len();
        // Change size is scaled by 4 from vBytes to weight units
        let change_weight = change_size.checked_mul(4).ok_or_else(|| {
            error!("Invalid change weight");
            TaprootDlcError::General("Invalid change weight".to_string())
        })?;

        // Base weight (nLocktime, nVersion, ...) is distributed among parties
        // independently of inputs contributed
        let this_party_fund_base_weight = util::FUND_TX_BASE_WEIGHT / 2;

        let total_fund_weight = checked_add!(
            this_party_fund_base_weight,
            inputs_weight,
            change_weight,
            36
        )?;
        let fund_fee = util::weight_to_fee(total_fund_weight, fee_rate_per_vb).map_err(|e| {
            error!("Failed to calculate fund fee: {}", e);
            TaprootDlcError::General("Failed to calculate fund fee".to_string())
        })?;

        // Base weight (nLocktime, nVersion, funding input ...) is distributed
        // among parties independently of output types
        let this_party_cet_base_weight = util::CET_BASE_WEIGHT / 2;

        // size of the payout script pubkey scaled by 4 from vBytes to weight units
        let output_spk_weight = self.payout_spk.len().checked_mul(4).ok_or_else(|| {
            error!("Invalid output spk weight");
            TaprootDlcError::General("Invalid output spk weight".to_string())
        })?;
        let total_cet_weight = checked_add!(this_party_cet_base_weight, output_spk_weight)?;
        let cet_or_refund_fee =
            util::weight_to_fee(total_cet_weight, fee_rate_per_vb).map_err(|e| {
                error!("Failed to calculate cet or refund fee: {}", e);
                TaprootDlcError::General("Failed to calculate cet or refund fee".to_string())
            })?;
        debug!("Fund fee: {}", fund_fee);
        debug!("Cet or refund fee: {}", cet_or_refund_fee);
        debug!("Input amount: {}", self.input_amount);
        let required_input_funds =
            checked_add!(self.collateral, fund_fee, cet_or_refund_fee, extra_fee)?;
        debug!("Required input funds: {}", required_input_funds);
        if self.input_amount < required_input_funds {
            error!("Insufficient input funds");
            return Err(TaprootDlcError::General(
                "Insufficient input funds".to_string(),
            ));
        }

        let change_output = TxOut {
            value: self.input_amount - required_input_funds,
            script_pubkey: self.change_spk.clone(),
        };

        Ok((change_output, fund_fee, cet_or_refund_fee))
    }

    pub fn get_unsigned_tx_inputs_and_serial_ids(
        &self,
        sequence: Sequence,
    ) -> (Vec<TxIn>, Vec<u64>) {
        let mut tx_ins = Vec::with_capacity(self.funding_tx_info.len());
        let mut serial_ids = Vec::with_capacity(self.funding_tx_info.len());

        for input in &self.funding_tx_info {
            let tx_in = TxIn {
                previous_output: input.outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            };
            tx_ins.push(tx_in);
            serial_ids.push(input.outpoint.vout as u64);
        }

        (tx_ins, serial_ids)
    }
}

pub(crate) async fn get_party_params<W: Deref, B: Deref>(
    // Should be generated by a signer and not set with the DlcParty
    funding_pubkey: XOnlyPublicKey,
    own_collateral: u64,
    fee_rate: u64,
    wallet: &W,
    blockchain: &B,
) -> Result<(PartyParams, Vec<FundingInput>), TaprootDlcError>
where
    W::Target: Wallet,
    B::Target: Blockchain,
{
    // let funding_pubkey = signer.get_public_key(secp)?;

    let payout_addr = wallet.get_new_address().map_err(|e| {
        error!("Failed to get new address: {}", e);
        TaprootDlcError::General("Failed to get new address".to_string())
    })?;
    let payout_spk = payout_addr.script_pubkey();
    let payout_serial_id = get_new_serial_id();
    let change_addr = wallet.get_new_change_address().map_err(|e| {
        error!("Failed to get new change address: {}", e);
        TaprootDlcError::General("Failed to get new change address".to_string())
    })?;
    let change_spk = change_addr.script_pubkey();
    let change_serial_id = get_new_serial_id();

    // Add base cost of fund tx + CET / 2 and a CET output to the collateral.
    let appr_required_amount = own_collateral
        + get_half_common_fee(fee_rate)?
        + util::weight_to_fee(124, fee_rate)
            .map_err(|e| {
                error!("Failed to calculate common fee: {}", e);
                TaprootDlcError::General("Failed to calculate common fee".to_string())
            })?
            .to_sat();

    let utxos = wallet
        .get_utxos_for_amount(appr_required_amount, fee_rate, false)
        .map_err(|e| {
            error!("Failed to get UTXOs: {}", e);
            TaprootDlcError::General(e.to_string())
        })?;

    let mut funding_inputs: Vec<FundingInput> = Vec::new();
    let mut funding_tx_info: Vec<TxInputInfo> = Vec::new();
    let mut total_input = Amount::ZERO;
    for utxo in utxos {
        let prev_tx = blockchain
            .get_transaction(&utxo.outpoint.txid)
            .await
            .unwrap();
        let mut writer = Vec::new();
        prev_tx.consensus_encode(&mut writer).unwrap();
        let prev_tx_vout = utxo.outpoint.vout;
        let sequence = 0xffffffff;
        // P2TR key-spend witness: signature (64 bytes) + sighash_type (1 byte) = 65 bytes
        let max_witness_len = 65;
        let funding_input = FundingInput {
            input_serial_id: get_new_serial_id(),
            prev_tx: writer,
            prev_tx_vout,
            sequence,
            max_witness_len,
            redeem_script: utxo.redeem_script,
        };
        total_input += prev_tx.output[prev_tx_vout as usize].value;
        funding_tx_info.push((&funding_input).into());
        funding_inputs.push(funding_input);
    }

    debug!(
        "Found {} funding inputs for collateral: {}",
        funding_inputs.len(),
        total_input
    );

    let party_params = PartyParams {
        fund_pubkey: funding_pubkey,
        change_serial_id,
        payout_spk,
        payout_serial_id,
        funding_tx_info,
        collateral: Amount::from_sat(own_collateral),
        input_amount: total_input,
        change_spk,
    };

    Ok((party_params, funding_inputs))
}

pub(crate) fn get_half_common_fee(fee_rate: u64) -> Result<u64, TaprootDlcError> {
    let common_fee = get_common_fee(fee_rate)?;
    Ok((common_fee as f64 / 2_f64).ceil() as u64)
}

/// Return the common base fee for a DLC for the given fee rate.
pub fn get_common_fee(fee_rate: u64) -> Result<u64, TaprootDlcError> {
    let base_weight = util::FUND_TX_BASE_WEIGHT + util::CET_BASE_WEIGHT;
    let fee = util::weight_to_fee(base_weight, fee_rate)
        .map_err(|e| {
            error!("Failed to calculate common fee: {}", e);
            TaprootDlcError::General("Failed to calculate common fee".to_string())
        })?
        .to_sat();
    Ok(fee)
}
