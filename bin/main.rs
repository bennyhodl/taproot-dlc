use bitcoin::{Amount, FeeRate, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use ddk::chain::EsploraClient;
use ddk_manager::contract::{
    contract_info::ContractInfo, enum_descriptor::EnumDescriptor, ser::Serializable,
    ContractDescriptor,
};
use dlc::{EnumerationPayout, Payout};
use kormir::OracleAnnouncement;
use taproot_dlc::{wallet::TaprootWallet, DlcParty, TaprootDlcError};
use tracing::Level;
use tracing_subscriber::fmt::Subscriber;

#[tokio::main]
async fn main() -> Result<(), TaprootDlcError> {
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
    let bob_wallet = TaprootWallet::wallet();

    fund_wallets(&alice_wallet, &bob_wallet, &client)?;

    let alice_blockchain = EsploraClient::new("http://localhost:30000", Network::Regtest).unwrap();
    let bob_blockchain = EsploraClient::new("http://localhost:30000", Network::Regtest).unwrap();

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
        .map_err(|e| {
            tracing::error!("Error offering DLC: {:?}", e);
            TaprootDlcError::General(e.to_string())
        })?;

    let accept = bob.accept_dlc(offer).await.map_err(|e| {
        tracing::error!("Error accepting DLC: {:?}", e);
        e
    })?;

    let signed = alice.sign_dlc(accept).await.map_err(|e| {
        tracing::error!("Error signing DLC: {:?}", e);
        e
    })?;

    let funding_transaction = alice.verify_sign_and_broadcast(signed).await.map_err(|e| {
        tracing::error!("Error verifying and broadcasting DLC: {:?}", e);
        e
    })?;

    tracing::info!(
        "Funding transaction: {:?}",
        hex::encode(funding_transaction.serialize().unwrap())
    );

    let broadcast = client
        .send_raw_transaction(&funding_transaction)
        .map_err(|e| {
            tracing::error!("Error broadcasting DLC: {:?}", e);
            TaprootDlcError::General(e.to_string())
        })?;

    tracing::info!("Broadcasted DLC: {:?}", broadcast);

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
                    offer: Amount::ONE_BTC.to_sat(),
                    accept: Amount::ZERO.to_sat(),
                },
            },
            EnumerationPayout {
                outcome: "OP_CTV".to_string(),
                payout: Payout {
                    offer: Amount::ZERO.to_sat(),
                    accept: Amount::ONE_BTC.to_sat(),
                },
            },
        ],
    };
    ContractDescriptor::Enum(enumeration_descriptor)
}

fn fund_wallets(
    alice_wallet: &TaprootWallet,
    bob_wallet: &TaprootWallet,
    client: &Client,
) -> Result<(), TaprootDlcError> {
    alice_wallet.faucet(Some(Amount::ONE_BTC), &client).unwrap();
    bob_wallet.faucet(Some(Amount::ONE_BTC), &client).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));
    alice_wallet.sync().unwrap();
    bob_wallet.sync().unwrap();
    tracing::info!(
        "Fauceted wallets: {:?}",
        alice_wallet.balance().unwrap().confirmed
    );
    tracing::info!(
        "Fauceted wallets: {:?}",
        bob_wallet.balance().unwrap().confirmed
    );
    if alice_wallet.balance().unwrap().confirmed < Amount::ONE_BTC
        || bob_wallet.balance().unwrap().confirmed < Amount::ONE_BTC
    {
        tracing::error!("Alice or Bob does not have enough balance");
        return Err(TaprootDlcError::General(
            "Alice or Bob does not have enough balance".to_string(),
        ));
    }

    Ok(())
}
