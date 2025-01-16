#![allow(dead_code, unused)]
mod port;
mod util;
mod wallet;

use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUALVERIFY};
use bitcoin::script::Builder;
use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, FeeRate, ScriptBuf, Sequence, TapNodeHash, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
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
use wallet::TaprootWallet;

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
    pub fn new(wallet: TaprootWallet, is_offerer: bool) -> Self {
        let secp = Secp256k1::new();
        let nonce_gen = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default();
        let context = Schnorr::<Sha256, _>::new(nonce_gen);

        // Generate a new random keypair, should use from the wallet
        // The keypair acts the same as the `ddk_manager::ContractSigner`.
        // We can really just generate a funding pubkey with an XOnlyPublicKey
        // ContractSigner and ContractSignerProvider.
        let keypair = context.new_keypair(Scalar::random(&mut thread_rng()));
        let funding_pubkey =
            XOnlyPublicKey::from_slice(&keypair.public_key().to_xonly_bytes()).unwrap();

        Self {
            secp,
            context,
            keypair,
            funding_pubkey,
            wallet,
            is_offerer,
        }
    }

    pub fn offer_dlc(
        &self,
        contract_info: ContractInfo,
        offer_collateral: Amount,
        total_collateral: Amount,
        fee_rate: FeeRate,
    ) -> Result<DlcOffer, TaprootDlcError> {
        let contract_id = new_temporary_id();

        let funding_inputs = self
            .wallet
            .get_utxos_for_amount(
                offer_collateral.to_sat(),
                fee_rate.to_sat_per_vb_ceil(),
                false,
            )
            .map_err(|e| TaprootDlcError::General(e.to_string()))?
            .iter()
            .map(|input| TxInputInfo {
                outpoint: input.outpoint,
                redeem_script: input.redeem_script.clone(),
                max_witness_len: 108,
                serial_id: input.outpoint.vout as u64,
            })
            .collect::<Vec<TxInputInfo>>();

        let payout_spk = self.wallet.get_new_address().unwrap().script_pubkey();
        let change_spk = self
            .wallet
            .get_new_change_address()
            .map_err(|_| TaprootDlcError::GetAddress)?
            .script_pubkey();
        if !change_spk.is_p2tr() {
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

        Ok(DlcOffer {
            contract_id,
            offer_params,
            contract_info,
            fee_rate,
            total_collateral,
        })
    }

    pub fn accept_dlc(&self, offer: DlcOffer) -> Result<DlcAccept, TaprootDlcError> {
        let accept_collateral = offer.total_collateral - offer.offer_params.collateral;

        let funding_inputs = self
            .wallet
            .get_utxos_for_amount(
                accept_collateral.to_sat(),
                offer.fee_rate.to_sat_per_vb_ceil(),
                false,
            )
            .map_err(|e| TaprootDlcError::General(e.to_string()))?
            .iter()
            .map(|input| TxInputInfo {
                outpoint: input.outpoint,
                redeem_script: input.redeem_script.clone(),
                max_witness_len: 108,
                serial_id: input.outpoint.vout as u64,
            })
            .collect::<Vec<TxInputInfo>>();

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

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &offer.contract_info.contract_descriptor,
            &offer.contract_info.oracle_announcements[0],
            offer.offer_params.payout_spk.clone(),
            accept_params.payout_spk.clone(),
        );

        Ok(DlcAccept {
            contract_id: offer.contract_id,
            accept_params,
            cet_adaptor_signatures,
            offer,
        })
    }

    pub fn sign_dlc(&self, accept: DlcAccept) -> Result<DlcSign, TaprootDlcError> {
        self.verify_adaptor_signatures(
            accept.accept_params.payout_spk.clone(),
            accept.offer.offer_params.payout_spk.clone(),
            &accept.offer.contract_info.contract_descriptor,
            accept.cet_adaptor_signatures.as_slice(),
            &accept.offer.contract_info.oracle_announcements[0],
            &accept,
        )?;

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &accept.offer.contract_info.contract_descriptor.clone(),
            &accept.offer.contract_info.oracle_announcements[0],
            accept.accept_params.payout_spk.clone(),
            accept.offer.offer_params.payout_spk.clone(),
        );

        // Sign half of the funding transaction
        let funding_transaction =
            self.create_funding_transaction(&accept, Amount::ONE_BTC, Amount::ONE_BTC)?;

        Ok(DlcSign {
            contract_id: accept.contract_id,
            cet_adaptor_signatures,
            funding_transaction,
            accept,
        })
    }

    // verify sign and broadcast
    pub fn verify_sign_and_broadcast(&self, _sign: DlcSign) -> Result<(), TaprootDlcError> {
        Ok(())
    }

    fn create_cet_adaptor_signatures(
        &self,
        contract_descriptor: &ContractDescriptor,
        announcement: &OracleAnnouncement,
        counterparty_script_pubkey: ScriptBuf,
        payout_script_pubkey: ScriptBuf,
    ) -> Vec<EncryptedSignature> {
        match contract_descriptor {
            ContractDescriptor::Enum(enumeration) => enumeration
                .outcome_payouts
                .iter()
                .enumerate()
                .map(|(i, outcome)| {
                    if counterparty_script_pubkey == payout_script_pubkey {
                        panic!("Counterparty pubkey is same as self pubkey!");
                    }
                    let cet = self
                        .build_cet(
                            &outcome,
                            counterparty_script_pubkey.clone(),
                            payout_script_pubkey.clone(),
                        )
                        .serialize()
                        .unwrap();

                    let nonce = announcement.oracle_event.oracle_nonces[i].clone();
                    let oracle_point = convert_xonly_to_normal_point(&nonce);

                    let message = Message::<Secret>::plain("cet", &cet);

                    // TODO: use a ContractSignerProvider providing XOnlyPublicKey and Scalar/PrivateKey
                    let encrypted_signature =
                        self.context
                            .encrypted_sign(&self.keypair, &oracle_point, message);

                    encrypted_signature
                })
                .collect(),
            ContractDescriptor::Numerical(_) => {
                println!("cant produce numerical");
                vec![]
            }
        }
    }

    fn build_cet(
        &self,
        outcome: &EnumerationPayout,
        counterparty_script_pubkey: ScriptBuf,
        my_script_pubkey: ScriptBuf,
    ) -> Transaction {
        let input = vec![];
        let mut output = vec![];

        let (offer_pubkey, accept_pubkey) = if self.is_offerer {
            (my_script_pubkey, counterparty_script_pubkey)
        } else {
            (counterparty_script_pubkey, my_script_pubkey)
        };

        if outcome.payout.offer > 0 {
            output.push(TxOut {
                script_pubkey: offer_pubkey,
                value: Amount::from_sat(outcome.payout.offer),
            });
        }

        if outcome.payout.accept > 0 {
            output.push(TxOut {
                script_pubkey: accept_pubkey,
                value: Amount::from_sat(outcome.payout.accept),
            });
        }

        // Make sure the total collateral matches the outputs

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output,
        };

        tx
    }

    fn verify_adaptor_signatures(
        &self,
        counterparty_script_pubkey: ScriptBuf,
        payout_script_pubkey: ScriptBuf,
        contract_descriptor: &ContractDescriptor,
        sigs: &[EncryptedSignature],
        announcement: &OracleAnnouncement,
        accept: &DlcAccept,
    ) -> Result<(), TaprootDlcError> {
        let payouts = match contract_descriptor {
            ContractDescriptor::Enum(e) => e.outcome_payouts.as_slice(),
            ContractDescriptor::Numerical(_) => return Err(TaprootDlcError::NumericContract),
        };
        for (i, signature) in sigs.iter().enumerate() {
            let nonce = announcement.oracle_event.oracle_nonces[i].clone();
            let oracle_point = convert_xonly_to_normal_point(&nonce);

            let cet = self
                .build_cet(
                    &payouts[i],
                    counterparty_script_pubkey.clone(),
                    payout_script_pubkey.clone(),
                )
                .serialize()
                .unwrap();
            let message = Message::<Secret>::plain("cet", &cet);

            let verify_key = if self.is_offerer {
                Point::<EvenY>::from_xonly_bytes(accept.accept_params.fund_pubkey.serialize())
                    .unwrap()
            } else {
                Point::<EvenY>::from_xonly_bytes(accept.offer.offer_params.fund_pubkey.serialize())
                    .unwrap()
            };

            if !self.context.verify_encrypted_signature(
                &verify_key,
                &oracle_point,
                message,
                signature,
            ) {
                return Err(TaprootDlcError::InvalidAdaptorSignature);
            }
        }
        Ok(())
    }

    fn decrypt_adaptor_signature(
        &self,
        oracle_signature: Signature,
        encrypted_signature: EncryptedSignature,
    ) -> Signature {
        let s = oracle_signature.s.non_zero().unwrap().secret();
        self.context.decrypt_signature(s, encrypted_signature)
    }

    fn create_funding_transaction(
        &self,
        accept_dlc: &DlcAccept,
        accept: Amount,
        offer: Amount,
    ) -> Result<Transaction, TaprootDlcError> {
        let funding_script = self.create_funding_script(&accept_dlc)?;

        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: accept + offer,
                script_pubkey: funding_script,
            }],
        };

        Ok(transaction)
    }

    fn create_funding_script(&self, accept: &DlcAccept) -> Result<ScriptBuf, TaprootDlcError> {
        // Can use the serial ordering in rust-dlc insteaf
        let (first_pubkey, second_pubkey) =
            if accept.offer.offer_params.fund_pubkey < accept.accept_params.fund_pubkey {
                (
                    accept.offer.offer_params.fund_pubkey,
                    accept.accept_params.fund_pubkey,
                )
            } else {
                (
                    accept.accept_params.fund_pubkey,
                    accept.offer.offer_params.fund_pubkey,
                )
            };

        let script_spend = Builder::new()
            .push_x_only_key(&first_pubkey)
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&second_pubkey)
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUALVERIFY)
            .into_script();

        let tap_tree = TapNodeHash::from_script(script_spend.as_script(), LeafVersion::TapScript);

        // Create an internal key using secp256kfun
        let internal_keypair = self
            .context
            .new_keypair(Scalar::random(&mut rand::thread_rng()));
        let internal_pubkey = internal_keypair.public_key().to_xonly_bytes();

        Ok(ScriptBuf::new_p2tr(
            &self.secp,
            XOnlyPublicKey::from_slice(&internal_pubkey).unwrap(),
            Some(tap_tree),
        ))
    }

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
        let my_sig = self
            .context
            .decrypt_signature(oracle_signature.s.non_zero().unwrap(), encrypted_signature);

        let counterparty_sig = self.context.decrypt_signature(
            oracle_signature.s.non_zero().unwrap(),
            counterparty_signature,
        );

        let funding_script = self.create_funding_script(&sign_dlc.accept)?;

        let tap_tree = TapNodeHash::from_script(funding_script.as_script(), LeafVersion::TapScript);

        // Throwaway pubkey
        let (internal_key, _) =
            bitcoin::secp256k1::Keypair::new(&self.secp, &mut rand::thread_rng())
                .x_only_public_key();

        let control_block = ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: bitcoin::key::Parity::Even,
            // i think this should be the internal key used above. Probably should be used
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
        Ok(cet.clone())
    }
}

fn new_temporary_id() -> [u8; 32] {
    thread_rng().gen::<[u8; 32]>()
}

fn convert_xonly_to_normal_point(x_only_pk: &XOnlyPublicKey) -> Point<Normal, Public, NonZero> {
    let xonly_bytess = x_only_pk.serialize();
    let oracle_point: Point<EvenY, Public, NonZero> =
        Point::from_xonly_bytes(xonly_bytess).unwrap();
    oracle_point.normalize()
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
        let alice = DlcParty::new(alice_wallet, true);
        let bob = DlcParty::new(bob_wallet, false);

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
