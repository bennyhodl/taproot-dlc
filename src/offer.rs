use crate::{party_params::PartyParams, util::get_tx_input_infos, DlcOffer, TaprootDlcError};
use bitcoin::{Amount, FeeRate, XOnlyPublicKey};
use ddk_manager::contract::contract_info::ContractInfo;

pub struct OfferedTaprootContract {
    pub id: [u8; 32],
    pub is_offer_party: bool,
    pub contract_info: ContractInfo,
    pub counter_party: XOnlyPublicKey,
    pub total_collateral: Amount,
    pub fee_rate: FeeRate,
    pub offer_params: PartyParams,
}

impl OfferedTaprootContract {
    pub fn try_from_offer(
        offer: DlcOffer,
        counter_party: XOnlyPublicKey,
    ) -> Result<Self, TaprootDlcError> {
        let (funding_tx_info, input_amount) = get_tx_input_infos(&offer.inputs)?;
        Ok(Self {
            id: offer.contract_id,
            is_offer_party: false,
            contract_info: offer.contract_info,
            counter_party,
            offer_params: PartyParams {
                fund_pubkey: offer.fund_pubkey,
                change_spk: offer.change_spk.clone(),
                change_serial_id: offer.change_serial_id,
                payout_spk: offer.payout_spk.clone(),
                payout_serial_id: offer.payout_serial_id,
                collateral: offer.collateral,
                funding_tx_info,
                input_amount,
            },
            total_collateral: offer.total_collateral,
            fee_rate: offer.fee_rate,
        })
    }
}
