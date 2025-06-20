use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use bdk_esplora::esplora_client::blocking::BlockingClient;
use bdk_esplora::esplora_client::Builder;
use bdk_esplora::EsploraExt;
use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::template::Bip86;
use bdk_wallet::{Balance, KeychainKind, SignOptions, Update, Utxo, Wallet as BdkWallet};
use bitcoin::bip32::Xpriv;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Transaction};
use bitcoincore_rpc::{Client, RpcApi};
use ddk::storage::memory::MemoryStorage;
use ddk_manager::error::Error;
use ddk_manager::{Blockchain, Wallet};
use rand::Fill;
use tracing::{debug, error};

use crate::{populate_psbt, FundingInput, TaprootDlcError};

pub struct TaprootWallet {
    pub wallet: RwLock<BdkWallet>,
    storage: MemoryStorage,
    blockchain: BlockingClient,
}

impl TaprootWallet {
    pub fn wallet() -> Self {
        let network = Network::Regtest;
        let secp = Secp256k1::new();
        let mut seed_bytes = [0u8; 32];
        seed_bytes
            .try_fill(&mut bitcoin::key::rand::thread_rng())
            .unwrap();

        let xprv = Xpriv::new_master(network, &seed_bytes).unwrap();

        let external_descriptor = Bip86(xprv, KeychainKind::External)
            .into_wallet_descriptor(&secp, network)
            .unwrap();
        let internal_descriptor = Bip86(xprv, KeychainKind::Internal)
            .into_wallet_descriptor(&secp, network)
            .unwrap();
        let wallet = BdkWallet::create(external_descriptor, internal_descriptor)
            .network(network)
            .create_wallet_no_persist()
            .unwrap();

        let blockchain = Builder::new("http://localhost:30000").build_blocking();

        Self {
            wallet: RwLock::new(wallet),
            storage: MemoryStorage::new(),
            blockchain,
        }
    }

    pub fn balance(&self) -> Result<Balance, Error> {
        let mut wallet = self.wallet.try_read().unwrap();
        Ok(wallet.balance())
    }

    pub fn sync(&self) -> anyhow::Result<()> {
        let mut wallet = self.wallet.try_write().unwrap();
        let prev_tip = wallet.latest_checkpoint();
        let spks = wallet
            .start_sync_with_revealed_spks()
            .chain_tip(prev_tip)
            .build();
        let sync = self.blockchain.sync(spks, 1)?;
        let indices = wallet.derivation_index(KeychainKind::External).unwrap_or(0);
        let internal_index = wallet.derivation_index(KeychainKind::Internal).unwrap_or(0);
        let mut last_active_indices = BTreeMap::new();
        last_active_indices.insert(KeychainKind::External, indices);
        last_active_indices.insert(KeychainKind::Internal, internal_index);
        let update = Update {
            last_active_indices,
            tx_update: sync.tx_update,
            chain: sync.chain_update,
        };
        wallet.apply_update(update)?;

        Ok(())
    }

    pub fn faucet(&self, amount: Option<Amount>, client: &Client) -> Result<(), anyhow::Error> {
        let mut wallet = self.wallet.try_write().unwrap();
        let address = wallet.next_unused_address(KeychainKind::External).address;
        tracing::info!("Fauceting to address: {}", address);
        client
            .send_to_address(
                &address,
                amount.unwrap(),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let faucet_address = client.get_new_address(None, None).unwrap();
        client
            .generate_to_address(10, &faucet_address.assume_checked())
            .unwrap();
        Ok(())
    }

    pub fn sign_funding_inputs(
        &self,
        transaction: &mut Transaction,
        all_funding_inputs: &[&FundingInput],
    ) -> Result<(), TaprootDlcError> {
        let mut psbt = Psbt::from_unsigned_tx(transaction.clone())
            .map_err(|e| TaprootDlcError::General(format!("Error creating psbt: {}", e)))?;

        populate_psbt(&mut psbt, all_funding_inputs)?;

        let mut wallet = self.wallet.try_write().unwrap();

        // Debug: Check what UTXOs we have
        debug!("Available UTXOs in wallet:");
        for utxo in wallet.list_unspent() {
            debug!("  UTXO: {} - {}", utxo.outpoint, utxo.txout.value);
        }

        debug!("Transaction inputs to sign:");
        for (i, input) in transaction.input.iter().enumerate() {
            debug!("  Input {}: {}", i, input.previous_output);

            if let Some(utxo) = wallet.get_utxo(input.previous_output) {
                debug!("    Found UTXO: {} sats", utxo.txout.value);
                psbt.inputs[i].witness_utxo = Some(utxo.txout.clone());
            } else {
                debug!("    UTXO not found in wallet (probably belongs to other party)");
            }
        }

        let sign_options = SignOptions {
            trust_witness_utxo: true,
            allow_grinding: true,
            try_finalize: true,
            ..Default::default()
        };

        // Try to sign
        match wallet.sign(&mut psbt, sign_options) {
            Ok(_) => {
                debug!("Successfully signed PSBT");
                *transaction = psbt.extract_tx().map_err(|e| {
                    TaprootDlcError::General(format!("Error extracting funding transaction: {}", e))
                })?;
                Ok(())
            }
            Err(e) => {
                error!("Failed to sign PSBT: {}", e);

                // Debug: Check which inputs have witness UTXOs
                for (i, input) in psbt.inputs.iter().enumerate() {
                    if input.witness_utxo.is_some() {
                        debug!("  Input {} has witness_utxo", i);
                    } else {
                        debug!("  Input {} missing witness_utxo", i);
                    }
                }

                Err(TaprootDlcError::General(format!(
                    "Error signing funding inputs: {}",
                    e
                )))
            }
        }
    }
}

impl Wallet for TaprootWallet {
    fn get_new_address(&self) -> Result<bitcoin::Address, Error> {
        let mut wallet = self.wallet.try_write().unwrap();
        Ok(wallet.next_unused_address(KeychainKind::External).address)
    }

    fn get_new_change_address(&self) -> Result<bitcoin::Address, Error> {
        let mut wallet = self.wallet.try_write().unwrap();
        Ok(wallet.next_unused_address(KeychainKind::Internal).address)
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        fee_rate: u64,
        lock_utxos: bool,
    ) -> Result<Vec<ddk_manager::Utxo>, Error> {
        let mut wallet = self.wallet.try_write().unwrap();
        Ok(wallet
            .list_unspent()
            .map(|utxo| {
                let address =
                    Address::from_script(&utxo.txout.script_pubkey, wallet.network()).unwrap();
                ddk_manager::Utxo {
                    tx_out: utxo.txout.clone(),
                    outpoint: utxo.outpoint,
                    address,
                    redeem_script: utxo.txout.script_pubkey,
                    reserved: false,
                }
            })
            .collect())
    }

    fn import_address(&self, address: &bitcoin::Address) -> Result<(), Error> {
        unimplemented!("No importing addresses for bdk_wallet")
    }

    fn sign_psbt_input(&self, psbt: &mut bitcoin::Psbt, input_index: usize) -> Result<(), Error> {
        let mut transaction = psbt.clone().extract_tx().unwrap();
        self.sign_funding_inputs(&mut transaction, &[]).unwrap();
        *psbt = Psbt::from_unsigned_tx(transaction).unwrap();
        Ok(())
    }

    fn unreserve_utxos(&self, outpoints: &[bitcoin::OutPoint]) -> Result<(), Error> {
        unimplemented!("not needed for bdk_wallet")
    }
}
