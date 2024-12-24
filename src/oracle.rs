use std::collections::HashMap;

use ddk::ddk_manager::contract::enum_descriptor::EnumDescriptor;
use kormir::{EnumEventDescriptor, EventDescriptor};
use rand::rngs::ThreadRng;
use schnorr_fun::{
    fun::{
        marker::{EvenY, NonZero, Normal, Public, Secret},
        KeyPair, Point, Scalar,
    },
    nonce::{GlobalRng, Synthetic},
    Message, Schnorr, Signature,
};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct OracleAnnouncement {
    /// The signature enabling verifying the origin of the announcement.
    pub announcement_signature: schnorr_fun::Signature,
    /// The public key of the oracle.
    pub oracle_public_key: Point<EvenY>,
    /// The description of the event and attesting.
    pub oracle_event: OracleEvent,
}

#[derive(Debug)]
pub struct OracleEvent {
    /// The nonces that the oracle will use to attest to the event outcome.
    pub oracle_nonces: Vec<Point<EvenY>>,
    /// The expected maturity of the contract.
    pub event_maturity_epoch: u32,
    /// The description of the event.
    pub event_descriptor: EventDescriptor,
    /// The id of the event.
    pub event_id: String,
}

pub struct Oracle {
    context: Schnorr<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>>,
    key_pair: KeyPair<EvenY>,
    nonces: HashMap<String, (Scalar<Secret, NonZero>, Point<EvenY, Public, NonZero>)>,
}

impl Oracle {
    pub fn new() -> Self {
        let nonce_gen = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default();
        let context = Schnorr::<Sha256, _>::new(nonce_gen);
        let key_pair = context.new_keypair(Scalar::random(&mut bitcoin::key::rand::thread_rng()));
        let nonces = HashMap::new();
        Self {
            context,
            key_pair,
            nonces,
        }
    }

    fn get_next_nonces(&mut self, outcomes: Vec<String>) -> Vec<Point<EvenY, Public, NonZero>> {
        let mut nonces = vec![];
        for outcome in outcomes {
            let nonce_gen = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default();
            let context = Schnorr::<Sha256, _>::new(nonce_gen);
            let key_pair =
                context.new_keypair(Scalar::random(&mut bitcoin::key::rand::thread_rng()));
            self.nonces.insert(
                outcome,
                (key_pair.secret_key().to_owned(), key_pair.public_key()),
            );
            nonces.push(key_pair.public_key());
        }
        nonces
    }

    pub fn create_announcement(&mut self, descriptor: EnumDescriptor) -> OracleAnnouncement {
        let outcomes = descriptor
            .outcome_payouts
            .iter()
            .map(|o| o.outcome.clone())
            .collect::<Vec<String>>();
        let nonces = self.get_next_nonces(outcomes.clone());

        // random signature because i dont feel like doin all the crap
        let signature = Signature::random(&mut bitcoin::key::rand::thread_rng());
        OracleAnnouncement {
            announcement_signature: signature,
            oracle_public_key: self.key_pair.public_key(),
            oracle_event: OracleEvent {
                oracle_nonces: nonces,
                event_maturity_epoch: 102342352,
                event_descriptor: EventDescriptor::EnumEvent(EnumEventDescriptor { outcomes }),
                event_id: "plz oracle work".to_string(),
            },
        }
    }

    pub fn sign_enum(&self, outcome: String) -> Signature {
        let nonce = self.nonces.get(&outcome).unwrap().to_owned();
        let key_pair = KeyPair::<EvenY>::new(nonce.0);
        let signature = self
            .context
            .sign(&key_pair, Message::<Public>::raw(&outcome.as_bytes()));

        println!("{:?}", &signature.to_bytes()[0..32]);
        println!("{:?}", nonce.1.to_xonly_bytes());

        signature
    }
}

#[cfg(test)]
mod tests {
    use dlc::{EnumerationPayout, Payout};

    use super::*;

    fn enum_desc() -> EnumDescriptor {
        EnumDescriptor {
            outcome_payouts: vec![
                EnumerationPayout {
                    outcome: "CAT".to_string(),
                    payout: Payout {
                        offer: 0,
                        accept: 0,
                    },
                },
                EnumerationPayout {
                    outcome: "CTV".to_string(),
                    payout: Payout {
                        offer: 0,
                        accept: 0,
                    },
                },
            ],
        }
    }

    #[test]
    fn oracle() {
        let mut oracle = Oracle::new();
        let announcment = oracle.create_announcement(enum_desc());
        println!("{:?}", announcment);
        oracle.sign_enum("CAT".to_string());
    }
}
