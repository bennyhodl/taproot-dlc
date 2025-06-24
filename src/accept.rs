use bitcoin::{ScriptBuf, Transaction};
use schnorr_fun::adaptor::EncryptedSignature;

use crate::{offer::OfferedTaprootContract, party_params::PartyParams, FundingInput};

/// Contains the necessary transactions for establishing a DLC
#[derive(Clone)]
pub struct DlcTransactions {
    /// The fund transaction locking both parties collaterals
    pub fund: Transaction,
    /// The contract execution transactions for closing the contract on a
    /// certain outcome
    pub cets: Vec<Transaction>,
    /// The refund transaction for returning the collateral for each party in
    /// case of an oracle misbehavior
    pub refund: Transaction,

    /// The script pubkey of the fund output in the fund transaction
    pub funding_script_pubkey: ScriptBuf,
}

pub struct AcceptedTaprootContract {
    pub offered_contract: OfferedTaprootContract,
    pub accept_params: PartyParams,
    pub funding_inputs: Vec<FundingInput>,
    // TODO: this is useful for numerical contracts
    // pub adaptor_infos: Vec<AdaptorInfo>,
    // TODO: potentially optional
    pub cet_adaptor_signatures: Vec<EncryptedSignature>,
    // TODO: handle refund signatures
    // pub accept_refund_signature: Option<Signature>,
    pub dlc_transactions: DlcTransactions,
}
