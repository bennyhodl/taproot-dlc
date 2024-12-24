use std::sync::RwLock;

use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::template::Bip86;
use bdk_wallet::{KeychainKind, SignOptions, Wallet as BdkWallet};
use bitcoin::bip32::Xpriv;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, ScriptBuf};
use ddk::ddk_manager::Wallet;
use ddk::storage::memory::MemoryStorage;
use rand::Fill;

pub struct TaprootWallet {
    wallet: RwLock<BdkWallet>,
    storage: MemoryStorage,
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

        Self {
            wallet: RwLock::new(wallet),
            storage: MemoryStorage::new(),
        }
    }
}
impl Wallet for TaprootWallet {
    fn get_new_address(&self) -> Result<bitcoin::Address, ddk::ddk_manager::error::Error> {
        let mut wallet = self.wallet.try_write().unwrap();
        Ok(wallet.next_unused_address(KeychainKind::External).address)
    }

    fn get_new_change_address(&self) -> Result<bitcoin::Address, ddk::ddk_manager::error::Error> {
        let mut wallet = self.wallet.try_write().unwrap();
        Ok(wallet.next_unused_address(KeychainKind::Internal).address)
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        fee_rate: u64,
        lock_utxos: bool,
    ) -> Result<Vec<ddk::ddk_manager::Utxo>, ddk::ddk_manager::error::Error> {
        let mut wallet = self.wallet.try_write().unwrap();
        Ok(wallet
            .list_unspent()
            .map(|utxo| {
                let address =
                    Address::from_script(&utxo.txout.script_pubkey, wallet.network()).unwrap();
                ddk::ddk_manager::Utxo {
                    tx_out: utxo.txout.clone(),
                    outpoint: utxo.outpoint,
                    address,
                    redeem_script: ScriptBuf::new(),
                    reserved: false,
                }
            })
            .collect())
    }

    fn import_address(
        &self,
        address: &bitcoin::Address,
    ) -> Result<(), ddk::ddk_manager::error::Error> {
        unimplemented!("No importing addresses for bdk_wallet")
    }

    fn sign_psbt_input(
        &self,
        psbt: &mut bitcoin::Psbt,
        input_index: usize,
    ) -> Result<(), ddk::ddk_manager::error::Error> {
        let mut wallet = self.wallet.try_write().unwrap();
        let sign_opts = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };

        let mut signed_psbt = psbt.clone();
        wallet
            .sign(&mut signed_psbt, sign_opts)
            .expect("could not sign psbt");

        psbt.inputs[input_index] = signed_psbt.inputs[input_index].clone();

        Ok(())
    }

    fn unreserve_utxos(
        &self,
        outpoints: &[bitcoin::OutPoint],
    ) -> Result<(), ddk::ddk_manager::error::Error> {
        unimplemented!("not needed for bdk_wallet")
    }
}
