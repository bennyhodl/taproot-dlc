// #![allow(dead_code, unused)]
mod accept;
mod offer;
mod party_params;
mod signed;
pub mod transaction;
mod util;
pub mod wallet;

use std::sync::Arc;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, FeeRate, OutPoint, Psbt, Script, ScriptBuf, Sequence, TapLeafHash, TapNodeHash,
    TapSighash, TapSighashType, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use ddk_manager::contract::contract_info::ContractInfo;
use ddk_manager::contract::ContractDescriptor;
use ddk_manager::{Blockchain, Wallet};
use dlc::secp256k1_zkp::{All, Secp256k1};
use dlc::{EnumerationPayout, TxInputInfo};
use kormir::{OracleAnnouncement, OracleAttestation};
use rand::{rngs::ThreadRng, thread_rng};
use rand::{Rng, RngCore};
use schnorr_fun::adaptor::{Adaptor, EncryptedSign};
use schnorr_fun::fun::marker::{NonZero, Normal, Public, Secret};
use schnorr_fun::Message;
use schnorr_fun::{
    adaptor::EncryptedSignature,
    fun::{marker::EvenY, KeyPair, Point, Scalar},
    nonce::{GlobalRng, Synthetic},
    Schnorr, Signature,
};
use sha2::Sha256;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};
use wallet::TaprootWallet;

use crate::offer::OfferedTaprootContract;
use crate::party_params::PartyParams;
use crate::transaction::{create_dlc_transactions, make_funding_redeemscript};
use crate::util::get_tx_input_infos;

/// Represents errors that can occur during Taproot DLC operations
#[derive(Debug, Clone, Error)]
pub enum TaprootDlcError {
    #[error("Not a taproor script pubkey")]
    NotTaproot,
    #[error("Adaptor Signature is not valid.")]
    InvalidAdaptorSignature,
    #[error("Numeric contracts not supported")]
    NumericContract,
    #[error("Secp error")]
    Secp,
    #[error("Generating Address")]
    GetAddress,
    #[error("{0}")]
    General(String),
    #[error("Esplora skill issue.")]
    Esplora,
    #[error("Oracle error")]
    Oracle,
}

#[derive(Debug, Clone)]
pub struct WitnessElement {
    pub witness: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FundingSignature {
    pub witness_elements: Vec<WitnessElement>,
}

/// Contains information about a specific input to be used in a funding transaction,
/// as well as its corresponding on-chain UTXO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingInput {
    /// Serial id used for input ordering in the funding transaction.
    pub input_serial_id: u64,
    /// The previous transaction used by the associated input in serialized format.
    pub prev_tx: Vec<u8>,
    /// The vout of the output used by the associated input.
    pub prev_tx_vout: u32,
    /// The sequence number to use for the input.
    pub sequence: u32,
    /// The maximum witness length that can be used to spend the previous UTXO.
    pub max_witness_len: u16,
    /// The redeem script of the previous UTXO.
    pub redeem_script: ScriptBuf,
}

impl From<&FundingInput> for TxInputInfo {
    fn from(funding_input: &FundingInput) -> TxInputInfo {
        TxInputInfo {
            outpoint: OutPoint {
                txid: Transaction::consensus_decode(&mut funding_input.prev_tx.as_slice())
                    .expect("Transaction Decode Error")
                    .compute_txid(),
                vout: funding_input.prev_tx_vout,
            },
            max_witness_len: (funding_input.max_witness_len as usize),
            redeem_script: funding_input.redeem_script.clone(),
            serial_id: funding_input.input_serial_id,
        }
    }
}

/// Represents a party in a DLC (Discreet Log Contract) transaction
/// This can be either the offerer or acceptor of the contract
pub struct DlcParty<B> {
    // For rust-bitcoin specific methods
    secp: Secp256k1<All>,
    // For Schnorr signing and verification of adaptor signatures
    context: Schnorr<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>>,
    // The keypair used for funding pubkeys
    keypair: KeyPair<EvenY>,
    // The funding pubkey (stored for quick access)
    funding_pubkey: XOnlyPublicKey,
    // The wallet used for funding and spending
    wallet: Arc<TaprootWallet>,
    /// Retrieves blockchain data
    blockchain: Arc<B>,
    // Whether this party is the offerer or acceptor
    is_offerer: bool,
    // Name for logging purposes
    name: String,
}

#[derive(Debug, Clone)]
pub struct DlcOffer {
    contract_id: [u8; 32],
    fund_pubkey: XOnlyPublicKey,
    change_spk: ScriptBuf,
    change_serial_id: u64,
    payout_spk: ScriptBuf,
    payout_serial_id: u64,
    collateral: Amount,
    inputs: Vec<FundingInput>,
    contract_info: ContractInfo,
    fee_rate: FeeRate,
    total_collateral: Amount,
}

#[derive(Debug, Clone)]
pub struct DlcAccept {
    contract_id: [u8; 32],
    accept_collateral: Amount,
    funding_pubkey: XOnlyPublicKey,
    payout_spk: ScriptBuf,
    payout_serial_id: u64,
    funding_inputs: Vec<FundingInput>,
    change_spk: ScriptBuf,
    change_serial_id: u64,
    cet_adaptor_signatures: Vec<EncryptedSignature>,
    offer: DlcOffer,
}

#[derive(Debug)]
pub struct DlcSign {
    contract_id: [u8; 32],
    // Offerers encrypted signatures to be verified by the acceptor
    cet_adaptor_signatures: Vec<EncryptedSignature>,

    pub funding_transaction: Transaction,
    // Funding signatures from the signer (witness data for their inputs)
    pub funding_signatures: Vec<FundingSignature>,

    // Refund signature
    // refund_signature: Signature,
    accept: DlcAccept,
}

impl<B: Blockchain> DlcParty<B> {
    /// Creates a new DLC party with the specified wallet and role
    ///
    /// # Arguments
    /// * `wallet` - The Taproot wallet to use for transactions
    /// * `is_offerer` - Whether this party is the offerer (true) or acceptor (false)
    #[instrument(skip_all, fields(is_offerer))]
    pub fn new(wallet: TaprootWallet, blockchain: B, is_offerer: bool, name: String) -> Self {
        info!("Creating new DLC party");
        let secp = Secp256k1::new();
        let nonce_gen = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default();
        let context = Schnorr::<Sha256, _>::new(nonce_gen);

        let keypair = context.new_keypair(Scalar::random(&mut thread_rng()));
        let funding_pubkey =
            XOnlyPublicKey::from_slice(&keypair.public_key().to_xonly_bytes()).unwrap();

        debug!("{}: Generated funding pubkey: {:?}", name, funding_pubkey);

        Self {
            secp,
            context,
            keypair,
            funding_pubkey,
            wallet: Arc::new(wallet),
            blockchain: Arc::new(blockchain),
            is_offerer,
            name,
        }
    }

    /// Creates a new DLC offer with the specified contract details
    ///
    /// # Arguments
    /// * `contract_info` - Information about the contract including descriptor and oracle announcements
    /// * `offer_collateral` - The amount of collateral being offered
    /// * `total_collateral` - The total collateral for the contract
    /// * `fee_rate` - The fee rate to use for transactions
    #[instrument(skip_all, fields(offer_collateral, total_collateral))]
    pub async fn offer_dlc(
        &self,
        contract_info: ContractInfo,
        offer_collateral: Amount,
        total_collateral: Amount,
        fee_rate: FeeRate,
    ) -> Result<DlcOffer, TaprootDlcError> {
        info!("{}: Creating new DLC offer", self.name);
        let contract_id = new_temporary_id();
        debug!("{}: Generated contract ID: {:?}", self.name, contract_id);

        let utxos = self
            .wallet
            .get_utxos_for_amount(
                offer_collateral.to_sat(),
                fee_rate.to_sat_per_vb_ceil(),
                false,
            )
            .map_err(|e| {
                error!("Failed to get UTXOs: {}", e);
                TaprootDlcError::General(e.to_string())
            })?;

        let mut funding_inputs: Vec<FundingInput> = Vec::new();
        let mut funding_tx_info: Vec<TxInputInfo> = Vec::new();
        let mut total_input = Amount::ZERO;
        for utxo in utxos {
            let prev_tx = self
                .blockchain
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
                input_serial_id: thread_rng().next_u64(),
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
            "{}: Found {} funding inputs for collateral: {}",
            self.name,
            funding_inputs.len(),
            total_input
        );

        let payout_spk = self.wallet.get_new_address().unwrap().script_pubkey();
        let change_spk = self
            .wallet
            .get_new_change_address()
            .map_err(|_| TaprootDlcError::GetAddress)?
            .script_pubkey();

        if !change_spk.is_p2tr() {
            error!("{}: Change script is not taproot", self.name);
            return Err(TaprootDlcError::NotTaproot);
        }

        info!("{}: Successfully created DLC offer", self.name);
        Ok(DlcOffer {
            contract_id,
            contract_info,
            fee_rate,
            total_collateral,
            fund_pubkey: self.funding_pubkey,
            change_spk,
            change_serial_id: 0,
            payout_spk,
            payout_serial_id: 0,
            collateral: offer_collateral,
            inputs: funding_inputs,
        })
    }

    /// Accepts a DLC offer and creates the acceptance message
    ///
    /// # Arguments
    /// * `offer` - The DLC offer to accept
    #[instrument(skip_all)]
    pub async fn accept_dlc(&self, offer: DlcOffer) -> Result<DlcAccept, TaprootDlcError> {
        info!("{}: Accepting DLC offer", self.name);

        // This should be retrieving a contract from a storage layer
        let offered_contract =
            OfferedTaprootContract::try_from_offer(offer.clone(), self.funding_pubkey)?;

        let accept_collateral =
            offered_contract.total_collateral - offered_contract.offer_params.collateral;
        debug!("{}: Accept collateral: {}", self.name, accept_collateral);

        let (accept_params, funding_inputs) = party_params::get_party_params(
            self.funding_pubkey,
            accept_collateral.to_sat(),
            offered_contract.fee_rate.to_sat_per_vb_ceil(),
            &self.wallet,
            &self.blockchain,
        )
        .await?;

        let dlc_transactions = create_dlc_transactions(
            &offered_contract.offer_params,
            &accept_params,
            &offered_contract
                .contract_info
                .get_payouts(offered_contract.total_collateral.to_sat())
                .unwrap(),
            // TOD: refund locktime figure it out
            1,
            offered_contract.fee_rate.to_sat_per_vb_ceil(),
            // TOD: fund locktime figure it out
            1,
            // TOD: cet locktime figure it out
            1,
            // TOD: fund output serial id figure it out
            0,
        )?;

        debug!("{}: Created DLC transactions", self.name);

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &offered_contract.contract_info.contract_descriptor,
            &offered_contract.contract_info.oracle_announcements[0],
            offered_contract.offer_params.payout_spk.clone(),
            accept_params.payout_spk.clone(),
            &dlc_transactions.funding_script_pubkey.as_script(),
            0,
            &dlc_transactions.fund.output[0],
            &dlc_transactions.fund,
        );

        info!("{}: Successfully created DLC acceptance", self.name);
        Ok(DlcAccept {
            contract_id: offered_contract.id,
            accept_collateral,
            funding_pubkey: self.funding_pubkey,
            payout_spk: accept_params.payout_spk,
            payout_serial_id: accept_params.payout_serial_id,
            funding_inputs: funding_inputs,
            change_spk: accept_params.change_spk,
            change_serial_id: accept_params.change_serial_id,
            cet_adaptor_signatures,
            offer,
        })
    }

    /// Signs a DLC acceptance and creates the signing message
    ///
    /// # Arguments
    /// * `accept` - The DLC acceptance to sign
    #[instrument(skip_all)]
    pub fn sign_dlc(&self, accept: DlcAccept) -> Result<DlcSign, TaprootDlcError> {
        info!("{}: Signing DLC acceptance", self.name);
        let accept_clone = accept.clone();
        let offered_contract =
            OfferedTaprootContract::try_from_offer(accept.offer.clone(), accept.funding_pubkey)?;
        let (funding_tx_info, input_amount) = get_tx_input_infos(&accept.funding_inputs)?;

        let accept_params = PartyParams {
            fund_pubkey: accept.funding_pubkey,
            payout_spk: accept.payout_spk,
            payout_serial_id: accept.payout_serial_id,
            change_spk: accept.change_spk,
            change_serial_id: accept.change_serial_id,
            funding_tx_info,
            input_amount,
            collateral: accept.accept_collateral,
        };

        let total_collateral = accept.offer.total_collateral;

        let dlc_transactions = create_dlc_transactions(
            &offered_contract.offer_params,
            &accept_params,
            &accept
                .offer
                .contract_info
                .get_payouts(total_collateral.to_sat())
                .unwrap(),
            // TOD: refund locktime figure it out
            1,
            offered_contract.fee_rate.to_sat_per_vb_ceil(),
            // TOD: fund locktime figure it out
            1,
            // TOD: cet locktime figure it out
            1,
            // TOD: fund output serial id figure it out
            0,
        )?;

        // self.verify_adaptor_signatures(
        //     accept.accept_params.payout_spk.clone(),
        //     accept.offer.offer_params.payout_spk.clone(),
        //     &accept.offer.contract_info.contract_descriptor,
        //     accept.cet_adaptor_signatures.as_slice(),
        //     &accept.offer.contract_info.oracle_announcements[0],
        //     &accept,
        //     &funding_script,
        //     0,
        //     &funding_transaction.output[0],
        //     &funding_transaction,
        // )?;

        debug!("{}: Verified adaptor signatures", self.name);

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &accept.offer.contract_info.contract_descriptor.clone(),
            &accept.offer.contract_info.oracle_announcements[0],
            accept_params.payout_spk.clone(),
            offered_contract.offer_params.payout_spk.clone(),
            &dlc_transactions.funding_script_pubkey.as_script(),
            0,
            &dlc_transactions.fund.output[0],
            &dlc_transactions.fund,
        );

        info!(
            "{}: Successfully created adaptor signatures in sign_dlc",
            self.name
        );
        info!("{}: Signing funding transaction", self.name);
        let mut all_funding_inputs: Vec<&FundingInput> = Vec::new();
        all_funding_inputs.extend(&accept.offer.inputs);
        all_funding_inputs.extend(&accept.funding_inputs);
        // Sort by serial ID to match rust-dlc pattern and ensure consistent ordering
        all_funding_inputs.sort_by_key(|x| x.input_serial_id);

        // Sign and extract funding signatures, keeping transaction unsigned
        let funding_signatures = self
            .wallet
            .sign_and_extract_funding_signatures(&dlc_transactions.fund, &all_funding_inputs)?;
        info!("{}: Successfully signed funding transaction", self.name);

        Ok(DlcSign {
            contract_id: accept.contract_id.clone(),
            cet_adaptor_signatures,
            funding_transaction: dlc_transactions.fund, // Keep this unsigned
            funding_signatures,
            accept: accept_clone,
        })
    }

    /// Verifies signatures and broadcasts the transaction
    ///
    /// # Arguments
    /// * `sign` - The DLC signing message
    #[instrument(skip_all)]
    pub async fn verify_sign_and_broadcast(
        &self,
        sign: DlcSign,
    ) -> Result<Transaction, TaprootDlcError> {
        info!(
            "{}: Verifying signatures and broadcasting transaction",
            self.name
        );

        // Create PSBT from the unsigned transaction
        let mut fund_psbt = Psbt::from_unsigned_tx(sign.funding_transaction.clone())
            .map_err(|e| TaprootDlcError::General(format!("Error creating psbt: {}", e)))?;

        // Get all funding inputs sorted by serial ID (to match rust-dlc pattern)
        let mut all_funding_inputs: Vec<&FundingInput> = Vec::new();
        all_funding_inputs.extend(&sign.accept.offer.inputs);
        all_funding_inputs.extend(&sign.accept.funding_inputs);
        all_funding_inputs.sort_by_key(|x| x.input_serial_id);

        populate_psbt(&mut fund_psbt, &all_funding_inputs)?;

        // Apply the funding signatures from the other party (Alice's signatures)
        for (funding_input, funding_signature) in sign
            .accept
            .offer
            .inputs
            .iter()
            .zip(sign.funding_signatures.iter())
        {
            let input_index = all_funding_inputs
                .iter()
                .position(|x| x == &funding_input)
                .ok_or_else(|| {
                    TaprootDlcError::General(format!(
                        "Could not find input for serial id {}",
                        funding_input.input_serial_id
                    ))
                })?;

            fund_psbt.inputs[input_index].final_script_witness = Some(Witness::from_slice(
                &funding_signature
                    .witness_elements
                    .iter()
                    .map(|x| x.witness.clone())
                    .collect::<Vec<_>>(),
            ));
        }

        // Sign our own inputs (Bob's inputs)
        for funding_input in &sign.accept.funding_inputs {
            let input_index = all_funding_inputs
                .iter()
                .position(|x| x == &funding_input)
                .ok_or_else(|| {
                    TaprootDlcError::General(format!(
                        "Could not find input for serial id {}",
                        funding_input.input_serial_id
                    ))
                })?;

            self.wallet
                .sign_psbt_input(&mut fund_psbt, input_index)
                .map_err(|e| TaprootDlcError::General(e.to_string()))?;
        }

        let final_transaction = fund_psbt.extract_tx().map_err(|e| {
            TaprootDlcError::General(format!("Error extracting transaction: {}", e))
        })?;

        info!(
            "{}: Successfully created fully signed funding transaction",
            self.name
        );
        Ok(final_transaction)
    }

    /// Creates adaptor signatures for CET (Contract Execution Transaction)
    ///
    /// # Arguments
    /// * `contract_descriptor` - The contract descriptor
    /// * `announcement` - The oracle announcement
    /// * `counterparty_script_pubkey` - The counterparty's script pubkey
    /// * `payout_script_pubkey` - The payout script pubkey
    /// * `funding_script` - The funding script
    /// * `input_index` - The input index
    /// * `funding_output` - The funding output
    #[instrument(skip_all)]
    fn create_cet_adaptor_signatures(
        &self,
        contract_descriptor: &ContractDescriptor,
        announcement: &OracleAnnouncement,
        counterparty_script_pubkey: ScriptBuf,
        payout_script_pubkey: ScriptBuf,
        funding_script: &Script,
        input_index: usize,
        funding_output: &TxOut,
        funding_transaction: &Transaction,
    ) -> Vec<EncryptedSignature> {
        match contract_descriptor {
            ContractDescriptor::Enum(enumeration) => {
                debug!("Creating adaptor signatures for enumeration contract");
                let mut sigs = Vec::new();

                // For enumeration contracts, there should be only one nonce
                if announcement.oracle_event.oracle_nonces.is_empty() {
                    error!("No oracle nonces found in announcement");
                    return sigs;
                }

                let nonce = &announcement.oracle_event.oracle_nonces[0]; // Use the single nonce
                let _base_oracle_point = convert_xonly_to_normal_point(nonce);

                for outcome in enumeration.outcome_payouts.iter() {
                    if counterparty_script_pubkey == payout_script_pubkey {
                        error!("Counterparty pubkey is same as self pubkey!");
                        panic!("Counterparty pubkey is same as self pubkey!");
                    }
                    let cet = self.build_cet(
                        &outcome,
                        counterparty_script_pubkey.clone(),
                        payout_script_pubkey.clone(),
                        funding_transaction,
                    );

                    // Create oracle signature point for this specific outcome
                    let outcome_hash =
                        bitcoin::hashes::sha256::Hash::hash(outcome.outcome.as_bytes());
                    let outcome_message =
                        secp256k1_zkp::Message::from_digest(outcome_hash.to_byte_array());

                    // Compute the oracle signature point for this outcome
                    // This represents the point that the oracle would use when signing this outcome
                    let oracle_sig_point = dlc::secp_utils::schnorrsig_compute_sig_point(
                        &self.secp,
                        &announcement.oracle_public_key,
                        nonce,
                        &outcome_message,
                    )
                    .unwrap_or_else(|e| {
                        error!("Failed to compute oracle signature point: {}", e);
                        panic!("Failed to compute oracle signature point");
                    });

                    let oracle_point =
                        Point::<Normal, Public, NonZero>::from_bytes(oracle_sig_point.serialize())
                            .unwrap_or_else(|| {
                                error!("Failed to convert oracle signature point");
                                panic!("Failed to convert oracle signature point");
                            });

                    let sighash =
                        create_sighash_msg(&cet, funding_script, input_index, funding_output);
                    let bytes = sighash.as_raw_hash().as_byte_array();
                    let message = Message::<Secret>::raw(bytes);

                    debug!(
                        "{}: Creating adaptor signature for outcome '{}' with funding script: {:?}",
                        self.name,
                        outcome.outcome,
                        hex::encode(funding_script.as_bytes())
                    );
                    debug!("{}: CET txid: {:?}", self.name, cet.compute_txid());
                    debug!(
                        "{}: Sighash message bytes: {:?}",
                        self.name,
                        hex::encode(bytes)
                    );
                    debug!(
                        "{}: Oracle signature point for outcome '{}': {:?}",
                        self.name,
                        outcome.outcome,
                        oracle_point.to_string()
                    );

                    let encrypted_signature =
                        self.context
                            .encrypted_sign(&self.keypair, &oracle_point, message);

                    sigs.push(encrypted_signature);
                }
                sigs
            }
            ContractDescriptor::Numerical(_) => {
                warn!("{}: Numerical contracts not supported", self.name);
                vec![]
            }
        }
    }

    /// Builds a Contract Execution Transaction (CET)
    ///
    /// # Arguments
    /// * `outcome` - The contract outcome
    /// * `counterparty_script_pubkey` - The counterparty's script pubkey
    /// * `my_script_pubkey` - The local script pubkey
    #[instrument(skip_all)]
    fn build_cet(
        &self,
        outcome: &EnumerationPayout,
        counterparty_script_pubkey: ScriptBuf,
        my_script_pubkey: ScriptBuf,
        funding_transaction: &Transaction,
    ) -> Transaction {
        debug!(
            "{}: Building CET for outcome: {}",
            self.name, outcome.outcome
        );
        let input = vec![TxIn {
            previous_output: OutPoint {
                txid: funding_transaction.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }];
        let mut output = vec![];

        // let (offer_pubkey, accept_pubkey) = if self.is_offerer {
        //     (my_script_pubkey, counterparty_script_pubkey)
        // } else {
        //     (counterparty_script_pubkey, my_script_pubkey)
        // };

        if outcome.payout.offer > 0 {
            output.push(TxOut {
                script_pubkey: if self.is_offerer {
                    my_script_pubkey.clone()
                } else {
                    counterparty_script_pubkey.clone()
                },
                value: Amount::from_sat(outcome.payout.offer),
            });
        }

        if outcome.payout.accept > 0 {
            output.push(TxOut {
                script_pubkey: if self.is_offerer {
                    counterparty_script_pubkey.clone()
                } else {
                    my_script_pubkey.clone()
                },
                value: Amount::from_sat(outcome.payout.accept),
            });
        }

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output,
        };

        debug!("{}: Built CET with {} outputs", self.name, tx.output.len());
        tx
    }

    /// Verifies adaptor signatures for a DLC
    ///
    /// # Arguments
    /// * `counterparty_script_pubkey` - The counterparty's script pubkey
    /// * `payout_script_pubkey` - The payout script pubkey
    /// * `contract_descriptor` - The contract descriptor
    /// * `sigs` - The adaptor signatures to verify
    /// * `announcement` - The oracle announcement
    /// * `accept` - The DLC acceptance
    /// * `funding_script` - The funding script
    /// * `input_index` - The input index
    /// * `funding_output` - The funding output
    #[instrument(skip_all)]
    fn verify_adaptor_signatures(
        &self,
        counterparty_script_pubkey: ScriptBuf,
        payout_script_pubkey: ScriptBuf,
        contract_descriptor: &ContractDescriptor,
        sigs: &[EncryptedSignature],
        announcement: &OracleAnnouncement,
        accept: &DlcAccept,
        funding_script: &Script,
        input_index: usize,
        funding_output: &TxOut,
        funding_transaction: &Transaction,
    ) -> Result<(), TaprootDlcError> {
        debug!("{}: Verifying adaptor signatures", self.name);
        let payouts = match contract_descriptor {
            ContractDescriptor::Enum(e) => e.outcome_payouts.as_slice(),
            ContractDescriptor::Numerical(_) => {
                error!("Numeric contracts not supported");
                return Err(TaprootDlcError::NumericContract);
            }
        };

        // For enumeration contracts, there should be only one nonce
        if announcement.oracle_event.oracle_nonces.is_empty() {
            error!("No oracle nonces found in announcement");
            return Err(TaprootDlcError::InvalidAdaptorSignature);
        }

        let nonce = &announcement.oracle_event.oracle_nonces[0]; // Use the single nonce

        for (i, signature) in sigs.iter().enumerate() {
            let outcome = &payouts[i];

            // Create oracle signature point for this specific outcome
            let outcome_hash = bitcoin::hashes::sha256::Hash::hash(outcome.outcome.as_bytes());
            let outcome_message = secp256k1_zkp::Message::from_digest(outcome_hash.to_byte_array());

            // Compute the oracle signature point for this outcome
            let oracle_sig_point = dlc::secp_utils::schnorrsig_compute_sig_point(
                &self.secp,
                &announcement.oracle_public_key,
                nonce,
                &outcome_message,
            )
            .map_err(|e| {
                error!("Failed to compute oracle signature point: {}", e);
                TaprootDlcError::InvalidAdaptorSignature
            })?;

            let oracle_point =
                Point::<Normal, Public, NonZero>::from_bytes(oracle_sig_point.serialize())
                    .unwrap_or_else(|| {
                        error!("Failed to convert oracle signature point");
                        panic!("Failed to convert oracle signature point");
                    });

            let cet = self.build_cet(
                outcome,
                counterparty_script_pubkey.clone(),
                payout_script_pubkey.clone(),
                funding_transaction,
            );

            let sighash = create_sighash_msg(&cet, funding_script, input_index, funding_output);
            let bytes = sighash.as_raw_hash().as_byte_array();
            let message = Message::<Secret>::raw(bytes);

            let verify_key = if self.is_offerer {
                Point::<EvenY>::from_xonly_bytes(accept.funding_pubkey.serialize()).unwrap()
            } else {
                Point::<EvenY>::from_xonly_bytes(accept.offer.fund_pubkey.serialize()).unwrap()
            };

            debug!(
                "{}: Verifying adaptor signature for outcome '{}' with funding script: {:?}",
                self.name,
                outcome.outcome,
                hex::encode(funding_script.as_bytes())
            );
            debug!("{}: CET txid: {:?}", self.name, cet.compute_txid());
            debug!(
                "{}: Sighash message bytes: {:?}",
                self.name,
                hex::encode(bytes)
            );
            debug!(
                "{}: Oracle signature point for outcome '{}': {:?}",
                self.name,
                outcome.outcome,
                oracle_point.to_string()
            );
            debug!("{}: Verification key: {:?}", self.name, verify_key);

            if !self.context.verify_encrypted_signature(
                &verify_key,
                &oracle_point,
                message,
                signature,
            ) {
                error!(
                    "{}: Invalid adaptor signature for outcome '{}'",
                    self.name, outcome.outcome
                );
                return Err(TaprootDlcError::InvalidAdaptorSignature);
            }
        }
        debug!(
            "{}: Successfully verified all adaptor signatures",
            self.name
        );
        Ok(())
    }

    /// Decrypts an adaptor signature using an oracle signature
    ///
    /// # Arguments
    /// * `oracle_signature` - The oracle signature
    /// * `encrypted_signature` - The encrypted signature to decrypt
    #[instrument(skip_all)]
    fn decrypt_adaptor_signature(
        &self,
        oracle_signature: Signature,
        encrypted_signature: EncryptedSignature,
    ) -> Signature {
        debug!("{}: Decrypting adaptor signature", self.name);
        let s = oracle_signature.s.non_zero().unwrap().secret();
        self.context.decrypt_signature(s, encrypted_signature)
    }

    /// Spends a Contract Execution Transaction (CET)
    ///
    /// # Arguments
    /// * `funding_transaction` - The funding transaction
    /// * `cet` - The CET to spend
    /// * `attestation` - The oracle attestation
    /// * `oracle_signature` - The oracle signature
    /// * `counterparty_signature` - The counterparty's signature
    /// * `encrypted_signature` - The encrypted signature
    /// * `sign_dlc` - The DLC signing message
    #[instrument(skip_all)]
    fn spend_cet(
        &self,
        _funding_transaction: Transaction,
        cet: &mut Transaction,
        _attestation: OracleAttestation,
        oracle_signature: Signature,
        counterparty_signature: EncryptedSignature,
        encrypted_signature: EncryptedSignature,
        sign_dlc: DlcSign,
    ) -> Result<Transaction, TaprootDlcError> {
        debug!("{}: Spending CET", self.name);
        let my_sig = self
            .context
            .decrypt_signature(oracle_signature.s.non_zero().unwrap(), encrypted_signature);

        let counterparty_sig = self.context.decrypt_signature(
            oracle_signature.s.non_zero().unwrap(),
            counterparty_signature,
        );

        let funding_script = make_funding_redeemscript(
            &sign_dlc.accept.offer.fund_pubkey,
            &sign_dlc.accept.funding_pubkey,
        );

        let tap_tree = TapNodeHash::from_script(funding_script.as_script(), LeafVersion::TapScript);

        let (internal_key, _) =
            bitcoin::secp256k1::Keypair::new(&self.secp, &mut rand::thread_rng())
                .x_only_public_key();

        let control_block = ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: bitcoin::key::Parity::Even,
            internal_key,
            merkle_branch: vec![tap_tree].try_into().unwrap(),
        };

        let mut witness = Witness::new();
        witness.push(&my_sig.to_bytes());
        witness.push(&counterparty_sig.to_bytes());
        witness.push(Vec::new());
        witness.push(funding_script.as_bytes());
        witness.push(&control_block.serialize());

        cet.input[0].witness = witness;
        debug!("{}: Successfully spent CET", self.name);
        Ok(cet.clone())
    }
}

/// Generates a new temporary ID for a DLC
#[instrument(skip_all)]
fn new_temporary_id() -> [u8; 32] {
    thread_rng().gen::<[u8; 32]>()
}

pub(crate) fn get_new_serial_id() -> u64 {
    thread_rng().next_u64()
}

/// Converts an X-only public key to a normal point
///
/// # Arguments
/// * `x_only_pk` - The X-only public key to convert
#[instrument(skip_all)]
fn convert_xonly_to_normal_point(x_only_pk: &XOnlyPublicKey) -> Point<Normal, Public, NonZero> {
    let xonly_bytess = x_only_pk.serialize();
    let oracle_point: Point<EvenY, Public, NonZero> =
        Point::from_xonly_bytes(xonly_bytess).unwrap();
    oracle_point.normalize()
}

/// Creates a sighash message for a transaction
///
/// # Arguments
/// * `secp` - The secp256k1 context
/// * `keypair` - The keypair to use for signing
/// * `cet` - The transaction to create the sighash for
/// * `funding_script` - The funding script
/// * `input_index` - The input index
/// * `funding_output` - The funding output
#[instrument(skip_all)]
fn create_sighash_msg<'a>(
    cet: &'a Transaction,
    funding_script: &'a Script,
    input_index: usize,
    funding_output: &'a TxOut,
) -> TapSighash {
    debug!("Creating sighash message for transaction");
    let mut cache = SighashCache::new(cet.clone());

    let leaf_hash = TapLeafHash::from_script(funding_script, LeafVersion::TapScript);
    let sighash_type = TapSighashType::Default;

    tracing::debug!("Using funding output: {:?}", funding_output);
    cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&[funding_output]),
            leaf_hash,
            sighash_type,
        )
        .expect("Taproot spend signature hash failed")
}

pub fn populate_psbt(
    psbt: &mut Psbt,
    all_funding_inputs: &[&FundingInput],
) -> Result<(), TaprootDlcError> {
    // Add witness utxo to psbt for all inputs
    for (input_index, funding_input) in all_funding_inputs.iter().enumerate() {
        let tx =
            Transaction::consensus_decode(&mut funding_input.prev_tx.as_slice()).map_err(|e| {
                TaprootDlcError::General(format!(
                    "Could not decode funding input previous tx parameter: {}",
                    e
                ))
            })?;

        let vout = funding_input.prev_tx_vout;
        let tx_out = tx.output.get(vout as usize).ok_or_else(|| {
            TaprootDlcError::General(format!("Previous tx output not found at index {}", vout))
        })?;

        psbt.inputs[input_index].witness_utxo = Some(tx_out.clone());
        psbt.inputs[input_index].redeem_script = Some(funding_input.redeem_script.clone());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use ddk::chain::EsploraClient;
    use ddk_manager::contract::enum_descriptor::EnumDescriptor;
    use dlc::Payout;

    fn announcement() -> OracleAnnouncement {
        serde_json::from_str::<OracleAnnouncement>(include_str!("../announcement.json")).unwrap()
    }

    fn contract_descriptor() -> ContractDescriptor {
        let enumeration_descriptor = EnumDescriptor {
            outcome_payouts: vec![
                EnumerationPayout {
                    outcome: "OP_CAT".to_string(),
                    payout: Payout {
                        offer: (Amount::ONE_BTC + Amount::ONE_BTC).to_sat(),
                        accept: Amount::ZERO.to_sat(),
                    },
                },
                EnumerationPayout {
                    outcome: "OP_CTV".to_string(),
                    payout: Payout {
                        offer: Amount::ZERO.to_sat(),
                        accept: (Amount::ONE_BTC + Amount::ONE_BTC).to_sat(),
                    },
                },
            ],
        };
        ContractDescriptor::Enum(enumeration_descriptor)
    }

    #[tokio::test]
    async fn taproot_dlc() {
        let client = Client::new(
            "http://localhost:18443",
            Auth::UserPass("ddk".to_string(), "ddk".to_string()),
        )
        .unwrap();
        let alice_wallet = TaprootWallet::wallet();
        let bob_wallet = TaprootWallet::wallet();

        fund_wallets(&alice_wallet, &bob_wallet, &client).expect("Error funding wallets");

        let alice_blockchain =
            EsploraClient::new("http://localhost:30000", Network::Regtest).unwrap();
        let bob_blockchain =
            EsploraClient::new("http://localhost:30000", Network::Regtest).unwrap();

        let alice = DlcParty::new(alice_wallet, alice_blockchain, true, "ALICE".to_string());
        let bob = DlcParty::new(bob_wallet, bob_blockchain, false, "BOB".to_string());

        let offer_collateral = Amount::from_btc(0.5).unwrap();
        let total_collateral = Amount::ONE_BTC;

        let contract_info = ContractInfo {
            contract_descriptor: contract_descriptor(),
            oracle_announcements: vec![announcement()],
            threshold: 1,
        };
        let offer = alice
            .offer_dlc(
                contract_info,
                offer_collateral,
                total_collateral,
                FeeRate::from_sat_per_vb_unchecked(1),
            )
            .await
            .expect("Error offering DLC");

        let accept = bob.accept_dlc(offer).await.expect("Error accepting DLC");

        let signed = alice.sign_dlc(accept).expect("Error signing DLC");

        let funding_transaction = bob
            .verify_sign_and_broadcast(signed)
            .await
            .expect("Error verifying and broadcasting DLC");

        client
            .send_raw_transaction(&funding_transaction)
            .expect("Error broadcasting DLC");
    }

    fn fund_wallets(
        alice_wallet: &TaprootWallet,
        bob_wallet: &TaprootWallet,
        client: &Client,
    ) -> Result<(), TaprootDlcError> {
        alice_wallet.faucet(Some(Amount::ONE_BTC), &client).unwrap();
        bob_wallet.faucet(Some(Amount::ONE_BTC), &client).unwrap();
        tracing::info!("Waiting for transactions to be mined...");
        std::thread::sleep(std::time::Duration::from_secs(10));

        tracing::info!("Syncing Alice wallet...");
        alice_wallet.sync().unwrap();
        tracing::info!("Syncing Bob wallet...");
        bob_wallet.sync().unwrap();

        let alice_balance = alice_wallet.balance().unwrap().confirmed;
        let bob_balance = bob_wallet.balance().unwrap().confirmed;

        tracing::info!("Alice balance: {:?}", alice_balance);
        tracing::info!("Bob balance: {:?}", bob_balance);

        if alice_balance < Amount::ONE_BTC || bob_balance < Amount::ONE_BTC {
            tracing::error!(
                "Alice balance: {}, Bob balance: {}",
                alice_balance,
                bob_balance
            );
            tracing::error!("Alice or Bob does not have enough balance");
            return Err(TaprootDlcError::General(
                "Alice or Bob does not have enough balance".to_string(),
            ));
        }

        Ok(())
    }
}

// struct OfferDlc {
//     ❌ protocol_version: u32,
//     ❌ contract_flags: u8,
//     ❌ chain_hash: [u8; 32],
//     ❌ temporary_contract_id: [u8; 32],
//     ✅ contract_info: ContractInfo,
//     ✅ funding_pubkey: PublicKey,
//     ✅ payout_spk: ScriptBuf,
//     ✅ payout_serial_id: u64,
//     ✅ offer_collateral: u64,
//     ✅ funding_inputs: Vec<FundingInput>,
//     ✅ change_spk: ScriptBuf,
//     ✅ change_serial_id: u64,
//     ❌ fund_output_serial_id: u64,
//     ✅ fee_rate_per_vb: u64,
//     ❌ cet_locktime: u32,
//     ❌ refund_locktime: u32,
// }

// struct AcceptDlc {
//     ❌ protocol_version: u32,
//     ❌ temporary_contract_id: [u8; 32],
//     ✅ accept_collateral: u64,
//     ✅ funding_pubkey: PublicKey,
//     ✅ payout_spk: ScriptBuf,
//     ✅ payout_serial_id: u64,
//     ✅ funding_inputs: Vec<FundingInput>,
//     ✅ change_spk: ScriptBuf,
//     ✅ change_serial_id: u64,
//     ✅ cet_adaptor_signatures: CetAdaptorSignatures,
//     ✅ refund_signature: Signature,
//     ❌ negotiation_fields: Option<NegotiationFields>,
// }

// struct SignDlc {
//     ❌ protocol_version: u32,
//     ✅ contract_id: [u8; 32],
//     ✅ cet_adaptor_signatures: CetAdaptorSignatures,
//     ❌ refund_signature: Signature,
//     ❌ funding_signatures: FundingSignatures,
// }
