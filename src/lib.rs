#![allow(dead_code, unused)]
mod port;
mod util;
pub mod wallet;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUALVERIFY};
use bitcoin::script::Builder;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, FeeRate, OutPoint, Script, ScriptBuf, Sequence, TapLeafHash, TapNodeHash, TapSighash,
    TapSighashType, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use ddk_manager::contract::contract_info::ContractInfo;
use ddk_manager::contract::ser::Serializable;
use ddk_manager::contract::ContractDescriptor;
use ddk_manager::Wallet;
use dlc::secp256k1_zkp::{All, Secp256k1};
use dlc::{EnumerationPayout, TxInputInfo};
use kormir::{OracleAnnouncement, OracleAttestation};
use rand::Rng;
use rand::{rngs::ThreadRng, thread_rng};
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

/// Represents a party in a DLC (Discreet Log Contract) transaction
/// This can be either the offerer or acceptor of the contract
pub struct DlcParty {
    // For rust-bitcoin specific methods
    secp: Secp256k1<All>,
    // For Schnorr signing and verification of adaptor signatures
    context: Schnorr<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>>,
    // The keypair used for funding pubkeys
    keypair: KeyPair<EvenY>,
    // The funding pubkey (stored for quick access)
    funding_pubkey: XOnlyPublicKey,
    // The wallet used for funding and spending
    wallet: TaprootWallet,
    // Whether this party is the offerer or acceptor
    is_offerer: bool,
    // Name for logging purposes
    name: String,
}

#[derive(Debug)]
pub struct PartyParams {
    fund_pubkey: XOnlyPublicKey,
    // The payout script for receiving the payout
    payout_spk: ScriptBuf,
    // The change script for receiving the change of a funding transaction
    change_spk: ScriptBuf,
    // The serial id of the change output
    change_serial_id: u64,
    // The serial id of the payout output
    payout_serial_id: u64,
    collateral: Amount,
    inputs: Vec<TxInputInfo>,
    input_amount: Amount,
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
    ) -> Result<(TxOut, Amount, Amount), dlc::Error> {
        let mut inputs_weight: usize = 0;

        for w in &self.inputs {
            let script_weight = util::redeem_script_to_script_sig(&w.redeem_script)
                .len()
                .checked_mul(4)
                .ok_or(dlc::Error::InvalidArgument)?;
            inputs_weight = crate::checked_add!(
                inputs_weight,
                crate::port::TX_INPUT_BASE_WEIGHT,
                script_weight,
                w.max_witness_len
            )?;
        }

        // Value size + script length var_int + ouput script pubkey size
        let change_size = self.change_spk.len();
        // Change size is scaled by 4 from vBytes to weight units
        let change_weight = change_size
            .checked_mul(4)
            .ok_or(dlc::Error::InvalidArgument)?;

        // Base weight (nLocktime, nVersion, ...) is distributed among parties
        // independently of inputs contributed
        let this_party_fund_base_weight = crate::port::FUND_TX_BASE_WEIGHT / 2;

        let total_fund_weight = checked_add!(
            this_party_fund_base_weight,
            inputs_weight,
            change_weight,
            36
        )?;
        let fund_fee = util::weight_to_fee(total_fund_weight, fee_rate_per_vb)?;

        // Base weight (nLocktime, nVersion, funding input ...) is distributed
        // among parties independently of output types
        let this_party_cet_base_weight = crate::port::CET_BASE_WEIGHT / 2;

        // size of the payout script pubkey scaled by 4 from vBytes to weight units
        let output_spk_weight = self
            .payout_spk
            .len()
            .checked_mul(4)
            .ok_or(dlc::Error::InvalidArgument)?;
        let total_cet_weight = checked_add!(this_party_cet_base_weight, output_spk_weight)?;
        let cet_or_refund_fee = util::weight_to_fee(total_cet_weight, fee_rate_per_vb)?;
        let required_input_funds =
            checked_add!(self.collateral, fund_fee, cet_or_refund_fee, extra_fee)?;
        if self.input_amount < required_input_funds {
            return Err(dlc::Error::InvalidArgument);
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
        let mut tx_ins = Vec::with_capacity(self.inputs.len());
        let mut serial_ids = Vec::with_capacity(self.inputs.len());

        for input in &self.inputs {
            let tx_in = TxIn {
                previous_output: input.outpoint,
                script_sig: util::redeem_script_to_script_sig(&input.redeem_script),
                sequence,
                witness: Witness::new(),
            };
            tx_ins.push(tx_in);
            serial_ids.push(input.outpoint.vout as u64);
        }

        (tx_ins, serial_ids)
    }
}

#[derive(Debug)]
pub struct DlcOffer {
    contract_id: [u8; 32],
    offer_params: PartyParams,
    contract_info: ContractInfo,
    fee_rate: FeeRate,
    total_collateral: Amount,
}

#[derive(Debug)]
pub struct DlcAccept {
    contract_id: [u8; 32],
    // Party params that acceptor shares back
    accept_params: PartyParams,
    // Encrypted signatures for each CET generated by the acceptor
    cet_adaptor_signatures: Vec<EncryptedSignature>,

    // TODO: refund signature
    // refund_signature: Signature,

    // Should be an offered contract that both parties
    // have stored so that they can get the contract
    // info and oracle announcements.
    offer: DlcOffer,
}

#[derive(Debug)]
pub struct DlcSign {
    contract_id: [u8; 32],
    // Offerers encrypted signatures to be verified by the acceptor
    cet_adaptor_signatures: Vec<EncryptedSignature>,

    // TODO The funding signatures for the acceptor to use to broadcast the funding transaction
    funding_transaction: Transaction,

    // Refund signature
    // refund_signature: Signature,
    accept: DlcAccept,
}

impl DlcParty {
    /// Creates a new DLC party with the specified wallet and role
    ///
    /// # Arguments
    /// * `wallet` - The Taproot wallet to use for transactions
    /// * `is_offerer` - Whether this party is the offerer (true) or acceptor (false)
    #[instrument(skip_all, fields(is_offerer))]
    pub fn new(wallet: TaprootWallet, is_offerer: bool, name: String) -> Self {
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
            wallet,
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
    pub fn offer_dlc(
        &self,
        contract_info: ContractInfo,
        offer_collateral: Amount,
        total_collateral: Amount,
        fee_rate: FeeRate,
    ) -> Result<DlcOffer, TaprootDlcError> {
        info!("{}: Creating new DLC offer", self.name);
        let contract_id = new_temporary_id();
        debug!("{}: Generated contract ID: {:?}", self.name, contract_id);

        let funding_inputs = self
            .wallet
            .get_utxos_for_amount(
                offer_collateral.to_sat(),
                fee_rate.to_sat_per_vb_ceil(),
                false,
            )
            .map_err(|e| {
                error!("Failed to get UTXOs: {}", e);
                TaprootDlcError::General(e.to_string())
            })?
            .iter()
            .map(|input| TxInputInfo {
                outpoint: input.outpoint,
                redeem_script: input.redeem_script.clone(),
                max_witness_len: 108,
                serial_id: input.outpoint.vout as u64,
            })
            .collect::<Vec<TxInputInfo>>();

        debug!(
            "{}: Found {} funding inputs",
            self.name,
            funding_inputs.len()
        );

        // check for inputs

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

        let offer_params = PartyParams {
            fund_pubkey: self.funding_pubkey,
            payout_spk,
            change_spk,
            collateral: offer_collateral,
            inputs: funding_inputs,
            input_amount: Amount::ZERO,
            change_serial_id: 0,
            payout_serial_id: 0,
        };

        info!("{}: Successfully created DLC offer", self.name);
        Ok(DlcOffer {
            contract_id,
            offer_params,
            contract_info,
            fee_rate,
            total_collateral,
        })
    }

    /// Accepts a DLC offer and creates the acceptance message
    ///
    /// # Arguments
    /// * `offer` - The DLC offer to accept
    #[instrument(skip_all)]
    pub fn accept_dlc(&self, offer: DlcOffer) -> Result<DlcAccept, TaprootDlcError> {
        info!("{}: Accepting DLC offer", self.name);
        let accept_collateral = offer.total_collateral - offer.offer_params.collateral;
        debug!("{}: Accept collateral: {}", self.name, accept_collateral);

        let funding_inputs = self
            .wallet
            .get_utxos_for_amount(
                accept_collateral.to_sat(),
                offer.fee_rate.to_sat_per_vb_ceil(),
                false,
            )
            .map_err(|e| {
                error!("Failed to get UTXOs: {}", e);
                TaprootDlcError::General(e.to_string())
            })?
            .iter()
            .map(|input| TxInputInfo {
                outpoint: input.outpoint,
                redeem_script: input.redeem_script.clone(),
                max_witness_len: 108,
                serial_id: input.outpoint.vout as u64,
            })
            .collect::<Vec<TxInputInfo>>();

        debug!(
            "{}: Found {} funding inputs",
            self.name,
            funding_inputs.len()
        );

        let payout_spk = self.wallet.get_new_address().unwrap().script_pubkey();
        let change_spk = self
            .wallet
            .get_new_change_address()
            .map_err(|_| TaprootDlcError::GetAddress)?
            .script_pubkey();

        let accept_params = PartyParams {
            fund_pubkey: self.funding_pubkey,
            change_spk,
            payout_spk,
            collateral: offer.total_collateral - offer.offer_params.collateral,
            inputs: funding_inputs,
            input_amount: Amount::ZERO,
            change_serial_id: 0,
            payout_serial_id: 0,
        };

        let (funding_transaction, funding_script) = self.create_funding_transaction(
            &offer.offer_params.fund_pubkey,
            &self.funding_pubkey,
            accept_collateral,
            offer.offer_params.collateral,
        )?;

        debug!("{}: Created funding transaction and script", self.name);

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &offer.contract_info.contract_descriptor,
            &offer.contract_info.oracle_announcements[0],
            offer.offer_params.payout_spk.clone(),
            accept_params.payout_spk.clone(),
            &funding_script.as_script(),
            0,
            &funding_transaction.output[0],
            &funding_transaction,
        );

        info!("{}: Successfully created DLC acceptance", self.name);
        Ok(DlcAccept {
            contract_id: offer.contract_id,
            accept_params,
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
        let (funding_transaction, funding_script) = self.create_funding_transaction(
            &accept.offer.offer_params.fund_pubkey,
            &accept.accept_params.fund_pubkey,
            accept.accept_params.collateral,
            accept.offer.offer_params.collateral,
        )?;

        debug!("{}: Created funding transaction and script", self.name);

        self.verify_adaptor_signatures(
            accept.accept_params.payout_spk.clone(),
            accept.offer.offer_params.payout_spk.clone(),
            &accept.offer.contract_info.contract_descriptor,
            accept.cet_adaptor_signatures.as_slice(),
            &accept.offer.contract_info.oracle_announcements[0],
            &accept,
            &funding_script,
            0,
            &funding_transaction.output[0],
            &funding_transaction,
        )?;

        debug!("{}: Verified adaptor signatures", self.name);

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &accept.offer.contract_info.contract_descriptor.clone(),
            &accept.offer.contract_info.oracle_announcements[0],
            accept.accept_params.payout_spk.clone(),
            accept.offer.offer_params.payout_spk.clone(),
            funding_script.as_script(),
            0,
            &funding_transaction.output[0],
            &funding_transaction,
        );

        info!("{}: Successfully signed DLC", self.name);
        Ok(DlcSign {
            contract_id: accept.contract_id,
            cet_adaptor_signatures,
            funding_transaction,
            accept,
        })
    }

    /// Verifies signatures and broadcasts the transaction
    ///
    /// # Arguments
    /// * `sign` - The DLC signing message
    #[instrument(skip_all)]
    pub fn verify_sign_and_broadcast(&self, _sign: DlcSign) -> Result<(), TaprootDlcError> {
        info!(
            "{}: Verifying signatures and broadcasting transaction",
            self.name
        );
        Ok(())
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
                enumeration
                    .outcome_payouts
                    .iter()
                    .enumerate()
                    .map(|(i, outcome)| {
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

                        let nonce = announcement.oracle_event.oracle_nonces[i].clone();
                        let oracle_point = convert_xonly_to_normal_point(&nonce);

                        let sighash = create_sighash_msg(
                            &self.secp,
                            &self.keypair,
                            &cet,
                            funding_script,
                            input_index,
                            funding_output,
                        );
                        let bytes = sighash.as_raw_hash().as_byte_array();
                        let message = Message::<Secret>::raw(bytes);

                        debug!(
                            "{}: Creating adaptor signature with funding script: {:?}",
                            self.name,
                            hex::encode(funding_script.as_bytes())
                        );
                        debug!("{}: CET txid: {:?}", self.name, cet.compute_txid());
                        debug!(
                            "{}: Sighash message bytes: {:?}",
                            self.name,
                            hex::encode(bytes)
                        );
                        debug!(
                            "{}: Oracle point: {:?}",
                            self.name,
                            oracle_point.to_string()
                        );

                        let encrypted_signature =
                            self.context
                                .encrypted_sign(&self.keypair, &oracle_point, message);

                        encrypted_signature
                    })
                    .collect()
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
        for (i, signature) in sigs.iter().enumerate() {
            let nonce = announcement.oracle_event.oracle_nonces[i].clone();
            let oracle_point = convert_xonly_to_normal_point(&nonce);

            let cet = self.build_cet(
                &payouts[i],
                counterparty_script_pubkey.clone(),
                payout_script_pubkey.clone(),
                funding_transaction,
            );

            let sighash = create_sighash_msg(
                &self.secp,
                &self.keypair,
                &cet,
                funding_script,
                input_index,
                funding_output,
            );
            let bytes = sighash.as_raw_hash().as_byte_array();
            let message = Message::<Secret>::raw(bytes);

            let verify_key = if self.is_offerer {
                Point::<EvenY>::from_xonly_bytes(accept.accept_params.fund_pubkey.serialize())
                    .unwrap()
            } else {
                Point::<EvenY>::from_xonly_bytes(accept.offer.offer_params.fund_pubkey.serialize())
                    .unwrap()
            };

            debug!(
                "{}: Verifying with funding script: {:?}",
                self.name,
                hex::encode(funding_script.as_bytes())
            );
            debug!("{}: CET txid: {:?}", self.name, cet.compute_txid());
            debug!(
                "{}: Sighash message bytes: {:?}",
                self.name,
                hex::encode(bytes)
            );
            debug!(
                "{}: Oracle point: {:?}",
                self.name,
                oracle_point.to_string()
            );
            debug!("{}: Verification key: {:?}", self.name, verify_key);

            if !self.context.verify_encrypted_signature(
                &verify_key,
                &oracle_point,
                message,
                signature,
            ) {
                error!("{}: Invalid adaptor signature", self.name);
                return Err(TaprootDlcError::InvalidAdaptorSignature);
            }
        }
        debug!("Successfully verified all adaptor signatures");
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

    /// Creates a funding transaction for the DLC
    ///
    /// # Arguments
    /// * `offer_pubkey` - The offerer's pubkey
    /// * `accept_pubkey` - The acceptor's pubkey
    /// * `accept` - The acceptor's collateral amount
    /// * `offer` - The offerer's collateral amount
    #[instrument(skip_all)]
    fn create_funding_transaction(
        &self,
        offer_pubkey: &XOnlyPublicKey,
        accept_pubkey: &XOnlyPublicKey,
        accept: Amount,
        offer: Amount,
    ) -> Result<(Transaction, ScriptBuf), TaprootDlcError> {
        debug!("{}: Creating funding transaction", self.name);
        let funding_script = self.create_funding_script(offer_pubkey, accept_pubkey)?;

        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: accept + offer,
                script_pubkey: funding_script.clone(),
            }],
        };

        debug!(
            "{}: Created funding transaction with value: {}",
            self.name,
            accept + offer
        );
        Ok((transaction, funding_script))
    }

    /// Creates a funding script for the DLC
    ///
    /// # Arguments
    /// * `offer_pubkey` - The offerer's pubkey
    /// * `accept_pubkey` - The acceptor's pubkey
    #[instrument(skip_all)]
    fn create_funding_script(
        &self,
        offer_pubkey: &XOnlyPublicKey,
        accept_pubkey: &XOnlyPublicKey,
    ) -> Result<ScriptBuf, TaprootDlcError> {
        debug!("{}: Creating funding script", self.name);
        let (first_pubkey, second_pubkey) = if offer_pubkey < accept_pubkey {
            (offer_pubkey, accept_pubkey)
        } else {
            (accept_pubkey, offer_pubkey)
        };

        debug!(
            "{}: Creating funding script with pubkeys: {:?} and {:?}",
            self.name,
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

        let mut hasher = bitcoin::hashes::sha256::Hash::engine();
        hasher.input(&first_pubkey.serialize());
        hasher.input(&second_pubkey.serialize());
        let seed_hash = bitcoin::hashes::sha256::Hash::from_engine(hasher);
        let seed = seed_hash.as_byte_array();
        let internal_keypair = self
            .context
            .new_keypair(Scalar::from_slice(&seed[..32]).unwrap());
        let internal_pubkey = internal_keypair.public_key().to_xonly_bytes();

        debug!(
            "Created funding script with tap tree: Internal pubkey: {:?}",
            hex::encode(internal_pubkey)
        );
        Ok(ScriptBuf::new_p2tr(
            &self.secp,
            XOnlyPublicKey::from_slice(&internal_pubkey).unwrap(),
            Some(tap_tree),
        ))
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

        let funding_script = self.create_funding_script(
            &sign_dlc.accept.offer.offer_params.fund_pubkey,
            &sign_dlc.accept.accept_params.fund_pubkey,
        )?;

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

/// Converts a schnorr_fun KeyPair to a secp256k1_zkp Keypair
fn convert_keypair(keypair: &KeyPair<EvenY>, secp: &Secp256k1<All>) -> secp256k1_zkp::Keypair {
    let secret_key =
        secp256k1_zkp::SecretKey::from_slice(&keypair.secret_key().to_bytes()).unwrap();
    secp256k1_zkp::Keypair::from_secret_key(&secp, &secret_key)
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
    secp: &Secp256k1<All>,
    keypair: &'a KeyPair<EvenY>,
    cet: &'a Transaction,
    funding_script: &'a Script,
    input_index: usize,
    funding_output: &'a TxOut,
) -> TapSighash {
    debug!("Creating sighash message for transaction");
    let mut cache = SighashCache::new(cet.clone());

    let leaf_hash = TapLeafHash::from_script(funding_script, LeafVersion::TapScript);
    let sighash_type = TapSighashType::Default;

    let mut prevouts = Vec::with_capacity(cet.input.len());
    for _ in 0..cet.input.len() {
        prevouts.push(funding_output);
    }
    let prevouts = Prevouts::All(&prevouts);

    cache
        .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
        .expect("Taproot spend signature hash failed")

    // // Convert the schnorr_fun keypair to secp256k1_zkp keypair
    // let secp_keypair = convert_keypair(keypair, secp);
    // let signature = secp.sign_schnorr_no_aux_rand(&hash.into(), &secp_keypair);

    // let sig = bitcoin::taproot::Signature {
    //     signature,
    //     sighash_type,
    // };

    // // Add signature to witness
    // let mut wit = cet.input[input_index].witness.to_vec();
    // tracing::debug!("Witness length: {:?}", wit.len());
    // let sig_bytes = sig.to_vec();
    // wit.insert(0, sig_bytes);
    // cet.input[input_index].witness = Witness::from(wit);

    // hash
}

#[cfg(test)]
mod tests {
    use super::*;
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
    #[test]
    fn taproot_dlc() {
        let alice_wallet = TaprootWallet::wallet();
        let bob_wallet = TaprootWallet::wallet();
        let alice = DlcParty::new(alice_wallet, true, "ALICE".to_string());
        let bob = DlcParty::new(bob_wallet, false, "BOB".to_string());

        let offer_collateral = Amount::ONE_BTC;
        let total_collateral = Amount::ONE_BTC + Amount::ONE_BTC;

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
            .unwrap();

        let accept = bob.accept_dlc(offer).unwrap();

        let _ = alice.sign_dlc(accept).unwrap();
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
