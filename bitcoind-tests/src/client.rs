// SPDX-License-Identifier: CC0-1.0

//! Wraps the `bitcoind` / `bitcoincore-rpc` client with balance tracking for regtest.
//!
//! ```no_run
//! # use bitcoind_tests::client::Client;
//! # use psbt_v2::bitcoin::Amount;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = Client::new()?;       // mines 100 blocks, tracker = 5000 BTC
//! client.mine_a_block()?;                // tracker += 50 BTC
//!
//! let address = client.wallet_address()?;
//! let txid = client.send(Amount::ONE_BTC, &address)?;
//! client.mine_a_block()?;
//! client.assert_balance_is_as_expected()?;
//!
//! // ... build, sign, finalize, and broadcast a PSBT ...
//!
//! let spend_amount = Amount::from_sat(50_000_000);
//! client.track_receive(spend_amount);
//! client.mine_a_block()?;
//! client.assert_balance_is_as_expected()?;
//! # Ok(())
//! # }
//! ```

// We depend upon and import directly from bitcoin because this module is not concerned with PSBT
// i.e., it is lower down the stack than the psbt_v2 crate.
use bitcoind::vtype::GetBlockchainInfo;
use bitcoind::{AddressType, BitcoinD};
use psbt_v2::bitcoin::{Address, Amount, Network, Transaction, Txid};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const FIFTY_BTC: Amount = Amount::from_int_btc(50);

/// A custom bitcoind client.
pub struct Client {
    /// Handle for the regtest `bitcoind` instance.
    bitcoind: BitcoinD,
    /// Tracks the expected wallet balance.
    tracker: BalanceTracker,
}

impl Client {
    /// The network the client runs on.
    pub const NETWORK: Network = Network::Regtest;

    /// Convenience constant: 1 BTC.
    pub const ONE_BTC: Amount = Amount::from_int_btc(1);

    /// The per-transaction fee used by both the balance tracker and PSBT change calculations.
    pub const FEE: Amount = Amount::from_sat(1_000);

    /// Creates a new [`Client`].
    pub fn new() -> Result<Self> {
        let exe_path = bitcoind::exe_path()?;
        let bitcoind = BitcoinD::new(exe_path)?;
        let tracker = BalanceTracker::zero();

        let client = Client { bitcoind, tracker };

        // Sanity check.
        assert_eq!(0, client.get_blockchain_info().unwrap().blocks);

        client.mine_blocks(100)?;
        assert_eq!(100, client.get_blockchain_info().unwrap().blocks);

        client.assert_balance_is_as_expected()?; // Sanity check.

        Ok(client)
    }

    /// Mines a block to a new address controlled by the currently loaded Bitcoin Core wallet.
    pub fn mine_a_block(&mut self) -> Result<()> {
        self.mine_blocks(1)?;
        self.tracker.mine_a_block();
        Ok(())
    }

    /// Returns the amount in the balance tracker.
    pub fn tracked_balance(&self) -> Amount { self.tracker.balance }

    /// Asserts that the tracker and the node agree on the wallet balance (to within 1 BTC).
    ///
    /// Queries the actual wallet balance from the node and compares it against the tracker.
    /// Differences smaller than 1 BTC are ignored so tests don't need to account for exact fees.
    #[track_caller]
    pub fn assert_balance_is_as_expected(&self) -> Result<()> {
        let balance = self.query_balance()?;
        self.tracker.assert(balance);
        Ok(())
    }

    /// Calls through to bitcoincore_rpc client.
    pub fn get_blockchain_info(&self) -> Result<GetBlockchainInfo> {
        let client = &self.bitcoind.client;
        Ok(client.get_blockchain_info()?)
    }

    /// Generates a new address from the wallet.
    pub fn wallet_address(&self) -> Result<Address> {
        let client = &self.bitcoind.client;
        // Use Bech32 (segwit v0) for compatibility with all Bitcoin Core versions.
        // Bech32m (taproot) is only available from Bitcoin Core 22.0+.
        let address = client.new_address_with_type(AddressType::Bech32)?;
        Ok(address)
    }

    /// Queries the actual balance from the Core wallet.
    pub fn query_balance(&self) -> Result<Amount> {
        let client = &self.bitcoind.client;
        let balance = client.get_balance()?.balance()?;
        Ok(balance)
    }

    /// Mines `n` blocks to a new address controlled by the currently loaded Bitcoin Core wallet.
    fn mine_blocks(&self, n: usize) -> Result<()> {
        let client = &self.bitcoind.client;
        // Generate to an address controlled by the bitcoind wallet and wait for funds to mature.
        let address = self.wallet_address()?;
        let _ = client.generate_to_address(n, &address)?;

        Ok(())
    }

    /// Sends `amount` to `address`, updating the balance tracker.
    ///
    /// Deducts `amount` plus an estimated fee from the balance tracker. If `address` is also
    /// a wallet address (funds didn't leave), follow up with [`Self::track_receive`] to cancel
    /// the amount deduction so only the fee remains.
    pub fn send(&mut self, amount: Amount, address: &Address) -> Result<Txid> {
        let client = &self.bitcoind.client;
        let txid = client.send_to_address(address, amount)?.txid()?;
        self.tracker.send(amount);
        Ok(txid)
    }

    /// Records a receive of `amount` in the balance tracker.
    ///
    /// Call this after a transaction that sends funds back into the wallet has been mined.
    pub fn track_receive(&mut self, amount: Amount) { self.tracker.receive(amount) }

    pub fn get_transaction(&self, txid: &Txid) -> Result<Transaction> {
        let client = &self.bitcoind.client;
        let res = client.get_transaction(*txid)?;
        let tx = res.into_model()?.tx;
        Ok(tx)
    }

    /// Calls `decodepsbt` on Bitcoin Core.
    pub fn decode_psbt(&self, psbt: &str) -> Result<()> {
        let client = &self.bitcoind.client;
        // `DecodePsbt` type not exported.
        let _ = client.decode_psbt(psbt)?;
        Ok(())
    }

    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid> {
        let client = &self.bitcoind.client;
        let txid = client.send_raw_transaction(tx)?.txid()?;
        Ok(txid)
    }
}

/// Tracks the amount we expect the wallet to hold.
///
/// We are sending whole bitcoin amounts back and forth, as a rough check that the transactions have
/// been mined we test against the integer floor of the amount, this allows us to not track fees.
struct BalanceTracker {
    balance: Amount,
}

impl BalanceTracker {
    /// Creates a new `BalanceTracker`.
    fn zero() -> Self { Self { balance: Amount::ZERO } }

    /// Every time we mine a block we release another coinbase reward.
    fn mine_a_block(&mut self) { self.balance += FIFTY_BTC }

    /// Update balance by sending `amount` (deducts amount + estimated fee).
    fn send(&mut self, amount: Amount) {
        self.balance = self.balance - amount - Client::FEE;
    }

    /// Update balance by receiving `amount`.
    fn receive(&mut self, amount: Amount) { self.balance += amount }

    /// Asserts balance against `want` ignoring everything except
    /// whole bitcoin, this allows us to ignore fees.
    #[track_caller]
    fn assert(&self, want: Amount) {
        let got = Self::floor(self.balance);
        let floor_want = Self::floor(want);
        if got != floor_want {
            panic!("We have {} but were expecting to have {} ({})", got, floor_want, want);
        }
    }

    /// Floors `x` to the nearest whole bitcoin.
    fn floor(x: Amount) -> Amount {
        let one_btc_in_sats = 100_000_000;
        let sats = x.to_sat();
        Amount::from_sat(sats / one_btc_in_sats * one_btc_in_sats)
    }
}
