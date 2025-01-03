#![allow(dead_code, unused)]
mod oracle;
mod wallet;

use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    opcodes::all::OP_CHECKMULTISIG,
    script::Builder,
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, TapTree, TaprootBuilder, TaprootMerkleBranch},
    transaction::Version,
    Address, Amount, FeeRate, PublicKey, Script, ScriptBuf, Sequence, TapLeafHash, TapNodeHash,
    TapSighash, TapSighashType, Transaction, TxIn, TxOut, Witness, WitnessProgram, WitnessVersion,
    XOnlyPublicKey,
};
use ddk::ddk_manager::contract::contract_info::ContractInfo;
use ddk::ddk_manager::contract::ser::Serializable;
use ddk::ddk_manager::contract::ContractDescriptor;
use ddk::ddk_manager::Wallet;
use ddk::wallet::DlcDevKitWallet;
use dlc::secp256k1_zkp::{All, Secp256k1};
use dlc::EnumerationPayout;
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
    secp: Secp256k1<All>,
    context: Schnorr<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>>,
    funding_keypair: KeyPair<EvenY>,
    payout_keypair: KeyPair<EvenY>,
    wallet: TaprootWallet,
    is_offerer: bool,
}

#[derive(Debug, Clone)]
pub struct PartyParams {
    fund_pubkey: Point<EvenY>,
    change_script_pubkey: ScriptBuf,
    // change_serial_id: u64,
    payout_address: Address,
    // payout_serial_id: u64,
    collateral: Amount,
    funding_inputs: Vec<TxIn>,
    // Amount that is in inputs
    funding_input_amount: Amount,
}

#[derive(Debug, Clone)]
pub struct DlcOffer {
    contract_id: [u8; 32],
    offer_params: PartyParams,
    contract_info: ContractInfo,
    fee_rate: FeeRate,
    total_collateral: Amount,
}

#[derive(Debug, Clone)]
pub struct DlcAccept {
    contract_id: [u8; 32],
    // Public keys that acceptor shares back
    accept_params: PartyParams,
    // Encrypted signatures for each CET
    cet_adaptor_signatures: Vec<EncryptedSignature>,
    offer: DlcOffer,
}

#[derive(Debug, Clone)]
pub struct DlcSign {
    // Offerers encrypted signatures
    cet_adaptor_signatures: Vec<EncryptedSignature>,
    // Funding signatures
    funding_transaction: Transaction,
    accept: DlcAccept,
}

impl DlcParty {
    pub fn new(wallet: TaprootWallet, is_offerer: bool) -> Self {
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
        let change_script_pubkey = self
            .wallet
            .get_new_change_address()
            .map_err(|_| TaprootDlcError::GetAddress)?
            .script_pubkey();

        if !change_script_pubkey.is_p2tr() {
            return Err(TaprootDlcError::NotTaproot);
        }

        let payout_address = self
            .wallet
            .get_new_address()
            .map_err(|_| TaprootDlcError::GetAddress)?;

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
            payout_address,
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

        let payout_address = self
            .wallet
            .get_new_address()
            .map_err(|_| TaprootDlcError::GetAddress)?;

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
            payout_address: payout_address.clone(),
            collateral: offer.total_collateral - offer.offer_params.collateral,
            funding_inputs,
            funding_input_amount: Amount::ZERO,
        };

        let mut accept = DlcAccept {
            contract_id: offer.contract_id,
            accept_params: accept_params.clone(),
            cet_adaptor_signatures: vec![],
            offer: offer.clone(),
        };

        let (funding_transaction, funding_script) = self.create_funding_transaction(
            &accept,
            accept_params.collateral.clone(),
            offer.offer_params.collateral.clone(),
        )?;

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &offer.contract_info.contract_descriptor,
            &offer.contract_info.oracle_announcements[0],
            offer.offer_params.payout_address.clone(),
            payout_address.clone(),
            offer.total_collateral,
            0,
            &funding_transaction.output[0],
            funding_script.as_script(),
        );

        accept.cet_adaptor_signatures = cet_adaptor_signatures;

        Ok(accept)
    }

    pub fn sign_dlc(&self, accept: DlcAccept) -> Result<DlcSign, TaprootDlcError> {
        self.verify_adaptor_signatures(
            accept.accept_params.payout_address.clone(),
            accept.offer.offer_params.payout_address.clone(),
            &accept.offer.contract_info.contract_descriptor,
            accept.cet_adaptor_signatures.as_slice(),
            &accept.offer.contract_info.oracle_announcements[0],
            accept.offer.total_collateral,
        )?;

        let (funding_transaction, funding_script) =
            self.create_funding_transaction(&accept, Amount::ONE_BTC, Amount::ONE_BTC)?;

        let cet_adaptor_signatures = self.create_cet_adaptor_signatures(
            &accept.offer.contract_info.contract_descriptor,
            &accept.offer.contract_info.oracle_announcements[0],
            accept.accept_params.payout_address.clone(),
            accept.offer.offer_params.payout_address.clone(),
            accept.offer.total_collateral,
            0,
            &funding_transaction.output[0],
            funding_script.as_script(),
        );

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
        counterparty_payout_address: Address,
        my_payout_address: Address,
        total_collateral: Amount,
        input_index: usize,
        funding_output: &TxOut,
        funding_script: &Script,
    ) -> Vec<EncryptedSignature> {
        match contract_descriptor {
            ContractDescriptor::Enum(enumeration) => enumeration
                .outcome_payouts
                .iter()
                .enumerate()
                .map(|(i, outcome)| {
                    let cet = self.build_cet(
                        &outcome,
                        counterparty_payout_address.clone(),
                        my_payout_address.clone(),
                        total_collateral,
                    );

                    let nonce = announcement.oracle_event.oracle_nonces[i].clone();
                    let oracle_point = convert_xonly_to_normal_point(&nonce);

                    let sighash =
                        create_sighash_msg(&cet, funding_script, input_index, funding_output);
                    let message = Message::<Secret>::raw(sighash.as_byte_array());

                    let encrypted_signature =
                        self.context
                            .encrypted_sign(&self.payout_keypair, &oracle_point, message);

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
        counterparty_payout_address: Address,
        my_payout_address: Address,
        _total_collateral: Amount,
    ) -> Transaction {
        let input = vec![];
        let mut output = vec![];

        let (offer_spk, accept_spk) = if self.is_offerer {
            (
                my_payout_address.script_pubkey(),
                counterparty_payout_address.script_pubkey(),
            )
        } else {
            (
                counterparty_payout_address.script_pubkey(),
                my_payout_address.script_pubkey(),
            )
        };

        if outcome.payout.offer > 0 {
            output.push(TxOut {
                script_pubkey: offer_spk,
                value: Amount::from_sat(outcome.payout.offer),
            });
        }

        if outcome.payout.accept > 0 {
            output.push(TxOut {
                script_pubkey: accept_spk,
                value: Amount::from_sat(outcome.payout.accept),
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
        counterparty_payout_address: Address,
        my_payout_address: Address,
        contract_descriptor: &ContractDescriptor,
        sigs: &[EncryptedSignature],
        announcement: &OracleAnnouncement,
        total_collateral: Amount,
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
                    counterparty_payout_address.clone(),
                    my_payout_address.clone(),
                    total_collateral,
                )
                .serialize()
                .unwrap();
            let message = Message::<Secret>::plain("cet", &cet);

            let x_only_pubkey =
                XOnlyPublicKey::from_slice(counterparty_payout_address.script_pubkey().as_bytes())
                    .map_err(|_| {
                        TaprootDlcError::General(
                            "Failed to convert payout address SPK to XOnlyPublicKey".to_string(),
                        )
                    })?;
            let payout_point: Point<EvenY, Public, NonZero> = Point::from_xonly_bytes(
                x_only_pubkey.serialize(),
            )
            .ok_or(TaprootDlcError::General(
                "Failed to create Point from XOnlyPublicKey".to_string(),
            ))?;

            if !self.context.verify_encrypted_signature(
                &payout_point,
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
    ) -> Result<(Transaction, ScriptBuf), TaprootDlcError> {
        let funding_script = self.create_funding_script(&accept_dlc)?;

        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: accept + offer,
                script_pubkey: funding_script.clone(),
            }],
        };

        Ok((transaction, funding_script))
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
        let my_sig = self
            .context
            .decrypt_signature(oracle_signature.s.non_zero().unwrap(), encrypted_signature);

        let counterparty_sig = self.context.decrypt_signature(
            oracle_signature.s.non_zero().unwrap(),
            counterparty_signature,
        );

        let (_, funding_script) = self.create_funding_transaction(
            &sign_dlc.accept,
            sign_dlc.accept.accept_params.collateral,
            sign_dlc.accept.offer.offer_params.collateral,
        )?;

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

fn convert_xonly_to_normal_point(x_only_pk: &XOnlyPublicKey) -> Point<Normal, Public, NonZero> {
    let xonly_bytess = x_only_pk.serialize();
    let oracle_point: Point<EvenY, Public, NonZero> =
        Point::from_xonly_bytes(xonly_bytess).unwrap();
    oracle_point.normalize()
}

fn point_to_p2tr_script(point: &Point<EvenY>, secp: &Secp256k1<All>) -> ScriptBuf {
    // Get x-only pubkey bytes
    let xonly_bytes = point.to_xonly_bytes();

    // Convert to XOnlyPublicKey first to ensure consistent encoding
    let xonly_pubkey = XOnlyPublicKey::from_slice(&xonly_bytes).expect("Valid x-only pubkey");

    ScriptBuf::new_p2tr(secp, xonly_pubkey, None)
}

fn create_sighash_msg<'a>(
    cet: &'a Transaction,
    funding_script: &'a Script,
    input_index: usize,
    funding_output: &'a TxOut,
) -> TapSighash {
    println!("Funding output: {:?}", funding_output);
    let leaf_hash = TapLeafHash::from_script(funding_script, LeafVersion::TapScript);

    let prevouts = Prevouts::One(input_index, funding_output);
    SighashCache::new(cet)
        .taproot_script_spend_signature_hash(
            input_index,
            &prevouts,
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap()
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
