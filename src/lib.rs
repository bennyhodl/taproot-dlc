#![allow(dead_code, unused)]
mod oracle;
mod wallet;

use bitcoin::taproot::{ControlBlock, TaprootMerkleBranch};
use ddk::ddk_manager::contract::contract_info::ContractInfo;
use ddk::ddk_manager::contract::ser::Serializable;
use ddk::ddk_manager::contract::ContractDescriptor;
use ddk::ddk_manager::Wallet;
use ddk::wallet::DlcDevKitWallet;
use dlc::secp256k1_zkp::{All, Secp256k1};
use dlc::EnumerationPayout;
use kormir::bitcoin::absolute::LockTime;
use kormir::bitcoin::opcodes::all::OP_CHECKMULTISIG;
use kormir::bitcoin::script::Builder;
use kormir::bitcoin::taproot::{LeafVersion, TapTree, TaprootBuilder};
use kormir::bitcoin::transaction::Version;
use kormir::bitcoin::{
    Amount, FeeRate, PublicKey, ScriptBuf, Sequence, TapNodeHash, Transaction, TxIn, TxOut,
    Witness, WitnessProgram, WitnessVersion, XOnlyPublicKey,
};
use kormir::{OracleAnnouncement, OracleAttestation};
use rand::Rng;
use rand::{rngs::ThreadRng, thread_rng};
use schnorr_fun::adaptor::{Adaptor, EncryptedSign};
use schnorr_fun::fun::marker::{NonZero, Normal, Secret};
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
}

pub struct DlcParty {
    secp: Secp256k1<All>,
    context: Schnorr<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>>,
    funding_keypair: KeyPair<EvenY>,
    payout_keypair: KeyPair<EvenY>,
    wallet: TaprootWallet,
}

#[derive(Debug)]
pub struct PartyParams {
    fund_pubkey: Point<EvenY>,
    change_script_pubkey: ScriptBuf,
    // change_serial_id: u64,
    payout_script_pubkey: Point<EvenY>,
    // payout_serial_id: u64,
    collateral: Amount,
    funding_inputs: Vec<TxIn>,
    // Amount that is in inputs
    funding_input_amount: Amount,
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
    // Public keys that acceptor shares back
    accept_params: PartyParams,
    // Encrypted signatures for each CET
    cet_adaptor_signatures: Vec<EncryptedSignature>,
    offer: DlcOffer,
}

#[derive(Debug)]
pub struct DlcSign {
    // Offerers encrypted signatures
    cet_adaptor_signatures: Vec<EncryptedSignature>,
    // Funding signatures
    funding_transaction: Transaction,
    accept: DlcAccept,
}

impl DlcParty {
    pub fn new(wallet: TaprootWallet) -> Self {
        let secp = Secp256k1::new();
        // Create Schnorr context with synthetic nonces
        let nonce_gen = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default();
        let context = Schnorr::<Sha256, _>::new(nonce_gen);

        // Generate a new random keypair
        let funding_keypair = context.new_keypair(Scalar::random(&mut thread_rng()));
        let payout_keypair = context.new_keypair(Scalar::random(&mut thread_rng()));
        Self {
            secp,
            context,
            funding_keypair,
            payout_keypair,
            wallet,
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
        let change_script_pubkey = self
            .wallet
            .get_new_change_address()
            .map_err(|_| TaprootDlcError::GetAddress)?
            .script_pubkey();

        if !change_script_pubkey.is_p2tr() {
            return Err(TaprootDlcError::NotTaproot);
        }

        let funding_inputs = self
            .wallet
            .get_utxos_for_amount(
                offer_collateral.to_sat(),
                fee_rate.to_sat_per_vb_ceil(),
                false,
            )
            .map_err(|e| TaprootDlcError::General(e.to_string()))?
            .iter()
            .map(|input| TxIn {
                previous_output: input.outpoint,
                script_sig: input.redeem_script.clone(),
                sequence: Sequence::MAX,
                // witness can be empty right?
                witness: Witness::default(),
            })
            .collect::<Vec<TxIn>>();

        let offer_params = PartyParams {
            fund_pubkey: self.funding_keypair.public_key(),
            payout_script_pubkey: self.payout_keypair.public_key(),
            change_script_pubkey,
            collateral: offer_collateral,
            funding_inputs,
            funding_input_amount: Amount::ZERO,
        };

        Ok(DlcOffer {
            contract_id: new_temporary_id(),
            offer_params,
            contract_info,
            fee_rate,
            total_collateral,
        })
    }

    pub fn accept_dlc(&self, offer: DlcOffer) -> Result<DlcAccept, TaprootDlcError> {
        let accept_collateral = offer.total_collateral - offer.offer_params.collateral;

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &offer.contract_info.contract_descriptor,
            &offer.contract_info.oracle_announcements[0],
            self.payout_keypair.public_key(),
            offer.total_collateral,
        );

        let change_script_pubkey = self
            .wallet
            .get_new_change_address()
            .map_err(|_| TaprootDlcError::GetAddress)?
            .script_pubkey();

        let funding_inputs = self
            .wallet
            .get_utxos_for_amount(
                accept_collateral.to_sat(),
                offer.fee_rate.to_sat_per_vb_ceil(),
                false,
            )
            .map_err(|e| TaprootDlcError::General(e.to_string()))?
            .iter()
            .map(|input| TxIn {
                previous_output: input.outpoint,
                script_sig: input.redeem_script.clone(),
                sequence: Sequence::MAX,
                // witness can be empty right?
                witness: Witness::default(),
            })
            .collect::<Vec<TxIn>>();

        let accept_params = PartyParams {
            fund_pubkey: self.funding_keypair.public_key(),
            change_script_pubkey,
            payout_script_pubkey: self.payout_keypair.public_key(),
            collateral: offer.total_collateral - offer.offer_params.collateral,
            funding_inputs,
            funding_input_amount: Amount::ZERO,
        };

        Ok(DlcAccept {
            contract_id: offer.contract_id,
            accept_params,
            cet_adaptor_signatures,
            offer,
        })
    }

    pub fn sign_dlc(&self, accept: DlcAccept) -> Result<DlcSign, TaprootDlcError> {
        self.verify_adaptor_signatures(
            accept.accept_params.payout_script_pubkey,
            &accept.offer.contract_info.contract_descriptor,
            accept.cet_adaptor_signatures.as_slice(),
            &accept.offer.contract_info.oracle_announcements[0],
            accept.offer.total_collateral,
        )?;

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &accept.offer.contract_info.contract_descriptor,
            &accept.offer.contract_info.oracle_announcements[0],
            self.payout_keypair.public_key(),
            accept.offer.total_collateral,
        );

        let funding_transaction =
            self.create_funding_transaction(&accept, Amount::ONE_BTC, Amount::ONE_BTC)?;

        Ok(DlcSign {
            cet_adaptor_signatures,
            funding_transaction,
            accept,
        })
    }

    fn create_cet_adaptor_signatures(
        &self,
        contract_descriptor: &ContractDescriptor,
        announcement: &OracleAnnouncement,
        counterparty_pubkey: Point<EvenY>,
        total_collateral: Amount,
    ) -> Vec<EncryptedSignature> {
        match contract_descriptor {
            ContractDescriptor::Enum(enumeration) => enumeration
                .outcome_payouts
                .iter()
                .enumerate()
                .map(|(i, outcome)| {
                    let cet = self.build_cet(&outcome, counterparty_pubkey, total_collateral);

                    let nonce = announcement.oracle_event.oracle_nonces[i].clone();
                    let oracle_point = convert_xonly_to_normal_point(&nonce);

                    let encrypted_signature = self.context.encrypted_sign(
                        &self.payout_keypair,
                        &oracle_point,
                        Message::<Secret>::plain("cet", &cet.serialize().unwrap()),
                    );

                    encrypted_signature
                })
                .collect(),
            ContractDescriptor::Numerical(_) => {
                println!("cant produce numerical");
                vec![]
            }
        }
    }

    // Need to specify who is offer and who is accept.
    fn build_cet(
        &self,
        outcome: &EnumerationPayout,
        counterparty_pubkey: Point<EvenY>,
        _total_collateral: Amount,
    ) -> Transaction {
        let input = vec![];
        let mut output = vec![];

        if outcome.payout.accept > 0 {
            output.push(TxOut {
                script_pubkey: point_to_p2tr_script(&self.payout_keypair.public_key()),
                value: Amount::from_sat(outcome.payout.accept),
            });
        }

        if outcome.payout.offer > 0 {
            output.push(TxOut {
                script_pubkey: point_to_p2tr_script(&counterparty_pubkey),
                value: Amount::from_sat(outcome.payout.offer),
            });
        }

        // Make sure the total collateral matches the outputs

        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output,
        }
    }

    fn verify_adaptor_signatures(
        &self,
        counterparty_pubkey: Point<EvenY>,
        contract_descriptor: &ContractDescriptor,
        sigs: &[EncryptedSignature],
        announcement: &OracleAnnouncement,
        total_collateral: Amount,
    ) -> Result<(), TaprootDlcError> {
        let payouts = match contract_descriptor {
            ContractDescriptor::Enum(e) => e.outcome_payouts.as_slice(),
            ContractDescriptor::Numerical(_) => return Err(TaprootDlcError::NumericContract),
        };
        println!("Verifying payouts: {:?}", payouts);
        for (i, signature) in sigs.iter().enumerate() {
            let nonce = announcement.oracle_event.oracle_nonces[i].clone();
            let oracle_point = convert_xonly_to_normal_point(&nonce);

            let cet = self.build_cet(&payouts[i], counterparty_pubkey, total_collateral);
            if !self.context.verify_encrypted_signature(
                &counterparty_pubkey,
                &oracle_point,
                Message::<Secret>::plain("cet", &cet.serialize().unwrap()),
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
        let (first_pubkey, second_pubkey) = if self.funding_keypair.public_key().to_xonly_bytes()
            < accept.accept_params.fund_pubkey.to_xonly_bytes()
        {
            (
                point_to_pubkey(self.funding_keypair.public_key())?,
                point_to_pubkey(accept.accept_params.fund_pubkey)?,
            )
        } else {
            (
                point_to_pubkey(accept.accept_params.fund_pubkey)?,
                point_to_pubkey(self.funding_keypair.public_key())?,
            )
        };

        let script_spend = Builder::new()
            .push_int(2)
            .push_key(&first_pubkey)
            .push_key(&second_pubkey)
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        let tap_tree = TapNodeHash::from_script(script_spend.as_script(), LeafVersion::TapScript);
        // Create an internal key using secp256kfun
        let internal_keypair = self
            .context
            .new_keypair(Scalar::random(&mut rand::thread_rng()));
        let internal_pubkey = internal_keypair.public_key();

        Ok(ScriptBuf::new_p2tr(
            &self.secp,
            XOnlyPublicKey::from_slice(&internal_pubkey.to_xonly_bytes()).unwrap(),
            Some(tap_tree),
        ))
    }

    fn spend_cet(
        &self,
        funding_transaction: Transaction,
        cet: &mut Transaction,
        attestation: OracleAttestation,
        oracle_signature: Signature,
        counterparty_signature: EncryptedSignature,
        encrypted_signature: EncryptedSignature,
        sign_dlc: DlcSign,
    ) -> Result<Transaction, TaprootDlcError> {
        let txin = TxIn {
            pe
        }
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![funding_transaction],
            output: vec![],
        };
        let my_sig = self
            .context
            .decrypt_signature(oracle_signature.s.non_zero().unwrap(), encrypted_signature);

        let counterparty_sig = self.context.decrypt_signature(
            oracle_signature.s.non_zero().unwrap(),
            counterparty_signature,
        );

        let funding_script = self.create_funding_script(&sign_dlc.accept)?;

        let tap_tree = TapNodeHash::from_script(funding_script.as_script(), LeafVersion::TapScript);

        let internal_keypair = self.context.new_keypair(Scalar::random(&mut thread_rng()));
        let internal_pubkey = internal_keypair.public_key();

        let control_block = ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: bitcoin::key::Parity::Even,
            // i think this should be the internal key used above. Probably should be used
            internal_key: XOnlyPublicKey::from_slice(&internal_pubkey.to_xonly_bytes())
                .map_err(|_| TaprootDlcError::Secp)?,
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

fn point_to_pubkey(point: Point<EvenY>) -> Result<PublicKey, TaprootDlcError> {
    let point_bytes = point.to_bytes();
    let pubkey = PublicKey::from_slice(&point_bytes).map_err(|_| TaprootDlcError::Secp)?;
    Ok(pubkey)
}

fn convert_xonly_to_normal_point(x_only_pk: &XOnlyPublicKey) -> Point<Normal, Secret, NonZero> {
    let xonly_bytess = x_only_pk.serialize();
    let oracle_point: Point<EvenY, Secret, NonZero> =
        Point::from_xonly_bytes(xonly_bytess).unwrap();
    oracle_point.normalize().secret()
}

fn point_to_p2tr_script(point: &Point<EvenY>) -> ScriptBuf {
    // Get x-only pubkey bytes
    let xonly_bytes = point.to_xonly_bytes();

    // Create witness program (this is how P2TR addresses are constructed)
    let witness_program = WitnessProgram::new(
        WitnessVersion::V1, // Taproot uses version 1
        &xonly_bytes[..],   // x-only pubkey bytes
    )
    .expect("Valid 32-byte public key");

    // Convert to ScriptBuf
    ScriptBuf::new_witness_program(&witness_program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use ddk::ddk_manager::{
        contract::{enum_descriptor::EnumDescriptor, numerical_descriptor::NumericalDescriptor},
        payout_curve::{
            PayoutFunction, PayoutFunctionPiece, PayoutPoint, PolynomialPayoutCurvePiece,
            RoundingInterval, RoundingIntervals,
        },
    };
    use dlc::Payout;
    use dlc_trie::OracleNumericInfo;
    use kormir::OracleAnnouncement;
    use rand::Fill;
    use std::sync::Arc;

    fn announcement() -> OracleAnnouncement {
        serde_json::from_str::<OracleAnnouncement>(include_str!("../announcement.json")).unwrap()
    }

    fn contract_descriptor() -> ContractDescriptor {
        // // Create payout points for a price range
        // let payout_points = vec![
        //     PayoutPoint {
        //         event_outcome: 0,   // $0
        //         extra_precision: 2, // 2 decimal places per oracle spec
        //         outcome_payout: 0,  // 0 sats
        //     },
        //     PayoutPoint {
        //         event_outcome: 50000, // $50,000
        //         extra_precision: 2,
        //         outcome_payout: 100000000, // 1 BTC
        //     },
        // ];

        // let function_pieces = PayoutFunctionPiece::PolynomialPayoutCurvePiece(
        //     PolynomialPayoutCurvePiece::new(payout_points).unwrap(),
        // );

        // let payout_function = PayoutFunction::new(vec![function_pieces]).unwrap();

        // // Create rounding interval (1 = no rounding)
        // let rounding_intervals = RoundingIntervals {
        //     intervals: vec![RoundingInterval {
        //         begin_interval: 0,
        //         rounding_mod: 1,
        //     }],
        // };

        // Set oracle info from the announcement
        let oracle_numeric_infos = OracleNumericInfo {
            base: 2,
            nb_digits: vec![20],
        };

        // let numerical_descriptor = NumericalDescriptor {
        //     payout_function,
        //     rounding_intervals,
        //     difference_params: None, // No difference params needed
        //     oracle_numeric_infos,
        // };

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
        // ContractDescriptor::Numerical(numerical_descriptor)
        ContractDescriptor::Enum(enumeration_descriptor)
    }
    #[test]
    fn taproot_dlc() {
        let alice_wallet = TaprootWallet::wallet();
        let bob_wallet = TaprootWallet::wallet();
        let alice = DlcParty::new(alice_wallet);
        let bob = DlcParty::new(bob_wallet);

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

        println!("{:?}", offer);

        let accept = bob.accept_dlc(offer).unwrap();
        println!("{:?}", accept);

        let _ = alice.sign_dlc(accept).unwrap();
    }
}
