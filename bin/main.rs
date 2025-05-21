use bitcoin::{Amount, FeeRate};
use bitcoincore_rpc::{Auth, Client};
use ddk_manager::contract::{
    contract_info::ContractInfo, enum_descriptor::EnumDescriptor, ContractDescriptor,
};
use dlc::{EnumerationPayout, Payout};
use kormir::OracleAnnouncement;
use taproot_dlc::{wallet::TaprootWallet, DlcParty, TaprootDlcError};
use tracing::Level;
use tracing_subscriber::fmt::Subscriber;

fn main() -> Result<(), TaprootDlcError> {
    tracing::subscriber::set_global_default(
        Subscriber::builder().with_max_level(Level::DEBUG).finish(),
    )
    .unwrap();

    let client = Client::new(
        "http://localhost:18443",
        Auth::UserPass("ddk".to_string(), "ddk".to_string()),
    )
    .unwrap();
    let alice_wallet = TaprootWallet::wallet();
    alice_wallet.faucet(Some(Amount::ONE_BTC), &client).unwrap();
    let bob_wallet = TaprootWallet::wallet();
    bob_wallet.faucet(Some(Amount::ONE_BTC), &client).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));
    alice_wallet.sync().unwrap();
    bob_wallet.sync().unwrap();
    tracing::info!("Fauceted wallets: {:?}", alice_wallet.balance().unwrap());
    tracing::info!("Fauceted wallets: {:?}", bob_wallet.balance().unwrap());
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
        .map_err(|e| {
            tracing::error!("Error offering DLC: {:?}", e);
            e
        })?;

    let accept = bob.accept_dlc(offer).map_err(|e| {
        tracing::error!("Error accepting DLC: {:?}", e);
        e
    })?;

    let _ = alice.sign_dlc(accept).map_err(|e| {
        tracing::error!("Error signing DLC: {:?}", e);
        e
    })?;

    Ok(())
}

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
