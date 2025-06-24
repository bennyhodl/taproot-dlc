use bitcoin::Transaction;

use crate::accept::AcceptedTaprootContract;
use crate::FundingSignature;
use crate::Signature;

pub struct SignedTaprootDlc {
    pub accepted_contract: AcceptedTaprootContract,
    pub funding_transaction: Transaction,
    pub funding_signatures: Vec<FundingSignature>,
    // pub refund_signature: Signature,
}
