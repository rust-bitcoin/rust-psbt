//! PSBT v2 2 of 2 multisig example - using BIP-32.
//!
//! An example of using PSBT v0 to create a 2 of 2 multisig by spending two native segwit v0 inputs
//! to a native segwit v0 output (the multisig output).
//!
//! We sign invalid inputs, this code is not run against Bitcoin Core so everything here should be
//! taken as NOT PROVEN CORRECT.
//!
//! This code is similar to `v0.rs` on purpose to show the differences between the APIs.

use bitcoin::transaction::Version;
use bitcoin::Transaction;
use psbt_v2::bitcoin::bip32::{DerivationPath, KeySource, Xpriv, Xpub};
use psbt_v2::bitcoin::hashes::Hash as _;
use psbt_v2::bitcoin::locktime::absolute;
use psbt_v2::bitcoin::opcodes::all::OP_CHECKMULTISIG;
use psbt_v2::bitcoin::secp256k1::{self, Secp256k1};
use psbt_v2::bitcoin::{
    script, Address, Amount, CompressedPublicKey, Network, OutPoint, PublicKey, ScriptBuf,
    Sequence, TxOut, Txid,
};
use psbt_v2::{
    combine, Constructor, InputBuilder, Modifiable, Output, OutputBuilder, Psbt, SignableInput,
    Signer, Updater,
};

const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
const SPEND_AMOUNT: Amount = Amount::from_sat(20_000_000);

const MAINNET: Network = Network::Bitcoin; // Bitcoin mainnet network.
const FEE: Amount = Amount::from_sat(1_000); // Usually this would be calculated.
const DUMMY_CHANGE_AMOUNT: Amount = Amount::from_sat(100_000);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Mimic two people, Alice and Bob, who wish to create a 2-of-2 multisig output together.
    let alice = Alice::new();
    let bob = Bob::new();

    // Each person provides the pubkey they want this multisig to be locked to.
    let pk_a = alice.multisig_public_key()?;
    let pk_b = bob.multisig_public_key()?;

    // Use of a locktime is of course optional.
    let min_required_height = absolute::Height::from_consensus(800_000).expect("valid height");

    // Each party will be contributing 20,000,000 sats to the mulitsig output, as such each party
    // provides an unspent input to create the multisig output (and any change details if needed).

    // Alice has a UTXO that is too big, she needs change.
    let (previous_output_a, change_address_a, change_value_a) = alice.contribute_to_multisig()?;

    // Bob has a UTXO the right size so no change needed.
    let previous_output_b = bob.contribute_to_multisig()?;

    // In PSBT v1 the creator and constructor roles can be the same entity, for an example of having
    // them separate see `./v2-separate-creator-constructor.rs`.

    // The constructor role.

    let constructor = Constructor::<Modifiable>::default();

    let input_a = InputBuilder::new(&previous_output_a)
        .minimum_required_height_based_lock_time(min_required_height)
        .build();

    // If no lock time is required we can just create the `Input` directly.
    let input_b = InputBuilder::new(&previous_output_b).legacy_fund(bob.funding_tx()?).build();

    // Build Alice's change output.
    let change = TxOut { value: change_value_a, script_pubkey: change_address_a.script_pubkey() };

    // Create the witness script, receive address, and the locking script.
    let witness_script = multisig_witness_script(&pk_a, &pk_b);
    let address = Address::p2wsh(&witness_script, MAINNET);
    let value = SPEND_AMOUNT * 2 - FEE;
    // The spend output is locked by the witness script.
    let multi = TxOut { value, script_pubkey: address.script_pubkey() };

    let psbt = constructor
        .input(input_a)
        .input(input_b)
        .output(OutputBuilder::new(multi).build())? // Use of the `OutputBuilder` is identical
        .output(Output::new(change))? // to just creating the `Output`.
        .psbt()
        .expect("valid lock time combination");

    // The updater role.

    // We can act as updater.
    let psbt = Updater::new(psbt)?.set_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF, 1)?.psbt();

    // Or we can get Alice and Bob to act as updaters.
    let updated_by_a = alice.update(psbt.clone())?;
    let updated_by_b = bob.update(psbt)?;

    let updated = combine(updated_by_a, updated_by_b)?;

    // The signer role.

    // Each party then acts in the signer role.
    let signed_by_a = alice.sign(updated.clone())?; // Asumes the user has verified the prevout
                                                    // amounts
    let signed_by_b = bob.sign_strict(updated)?; // Fails if input fails to provide enough data to
                                                 // verify prevout amounts

    let _signed = combine(signed_by_a, signed_by_b);

    // At this stage we would usually finalize with miniscript and extract the transaction.

    Ok(())
}

/// Creates a 2-of-2 multisig script locking to a and b's keys.
fn multisig_witness_script(a: &PublicKey, b: &PublicKey) -> ScriptBuf {
    script::Builder::new()
        .push_int(2)
        .push_key(a)
        .push_key(b)
        .push_int(2)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

/// Party 1 in a 2-of-2 multisig.
pub struct Alice(Entity);

impl Alice {
    /// The derivation path associated with the dummy utxo we are spending.
    const PATH: &'static str = "m/84'/0'/0'/0/42";

    /// Creates a new Alice.
    pub fn new() -> Self {
        let seed = [0x00; 32]; // Fake example with a fake seed :)
        let xpriv = Xpriv::new_master(MAINNET, &seed).unwrap();

        Self(Entity::new(xpriv))
    }

    /// Returns the public key for this entity.
    pub fn multisig_public_key(&self) -> Result<bitcoin::PublicKey, Box<dyn std::error::Error>> {
        self.0.public_key("m/84'/0'/0'/123")
    }

    /// Alice provides an input to be used to create the multisig and the details required to get
    /// some change back (change address and amount).
    pub fn contribute_to_multisig(
        &self,
    ) -> Result<(OutPoint, Address, Amount), Box<dyn std::error::Error>> {
        // An obviously invalid output, we just use all zeros then use the `vout` to differentiate
        // Alice's output from Bob's.
        let out = OutPoint { txid: Txid::all_zeros(), vout: 0 };

        // The usual caveat about reusing addresses applies here, this is just an example.
        let compressed =
            CompressedPublicKey::try_from(self.multisig_public_key()?).expect("uncompressed key");
        let address = Address::p2wpkh(&compressed, Network::Bitcoin);

        // This is a made up value, it is supposed to represent the outpoints value minus the value
        // contributed to the multisig.
        let amount = DUMMY_CHANGE_AMOUNT;

        Ok((out, address, amount))
    }

    /// Signs `psbt`.
    pub fn sign(&self, psbt: Psbt) -> Result<Psbt, Box<dyn std::error::Error>> {
        self.0.sign_ecdsa(psbt, Self::PATH)
    }

    /// Alice updates the PSBT, adding her utxo and key source.
    pub fn update(&self, mut psbt: Psbt) -> Result<Psbt, Box<dyn std::error::Error>> {
        let input = &mut psbt.inputs[0];

        // The dummy input utxo we are spending and the pubkey/keysource that will be used to sign it.
        input.witness_utxo = Some(self.input_utxo()?);
        let (pk, key_source) = self.bip32_derivation()?;
        input.bip32_derivations.insert(pk, key_source);
        Ok(psbt)
    }

    /// Provides the actual UTXO that Alice is contributing, this would usually come from the chain.
    fn input_utxo(&self) -> Result<TxOut, Box<dyn std::error::Error>> {
        self.0.input_utxo(Self::PATH)
    }

    fn bip32_derivation(&self) -> Result<(PublicKey, KeySource), Box<dyn std::error::Error>> {
        self.0.bip32_derivation(Self::PATH)
    }
}

impl Default for Alice {
    fn default() -> Self { Self::new() }
}

/// Party 2 in a 2-of-2 multisig.
pub struct Bob(Entity);

impl Bob {
    /// The derivation path associated with the dummy utxo we are spending.
    const PATH: &'static str = "m/84'/0'/0'/0/0";

    /// Creates a new Bob.
    pub fn new() -> Self {
        let seed = [0x11; 32]; // Fake example with a fake seed :)
        let xpriv = Xpriv::new_master(MAINNET, &seed).unwrap();

        Self(Entity::new(xpriv))
    }

    /// Returns the public key for this entity.
    pub fn multisig_public_key(&self) -> Result<bitcoin::PublicKey, Box<dyn std::error::Error>> {
        self.0.public_key("m/84'/0'/0'/20")
    }

    /// Provide the original full funding tx
    pub fn funding_tx(&self) -> Result<Transaction, Box<dyn std::error::Error>> {
        Ok(Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![self.input_utxo()?],
        })
    }

    /// Bob provides an input to be used to create the multisig, its the right size so no change.
    pub fn contribute_to_multisig(&self) -> Result<OutPoint, Box<dyn std::error::Error>> {
        let tx = self.funding_tx()?;
        let txid = tx.compute_txid();
        Ok(OutPoint { txid, vout: 0 })
    }

    /// Signs `psbt` enforcing verification of input prevout amounts
    pub fn sign_strict(&self, psbt: Psbt) -> Result<Psbt, Box<dyn std::error::Error>> {
        // Usually we'd have to check this was our input and provide the correct key.
        let path = Self::PATH.parse::<DerivationPath>()?;
        let xpriv = self.0.master.derive_priv(&self.0.secp, &path)?;

        let mut signer = Signer::new(psbt)?;
        let sigs = {
            let mut session = signer.session();
            let inputs: SignableInput = session
                .signable_input(1)
                .expect("owned input with full tx prevout should be verifiable");
            session.get_all(&[inputs], &xpriv, &self.0.secp)
        };
        let psbt = signer.apply(sigs).unwrap();
        Ok(psbt)
    }

    /// Alice updates the PSBT, adding her utxo and key source.
    pub fn update(&self, mut psbt: Psbt) -> Result<Psbt, Box<dyn std::error::Error>> {
        let input = &mut psbt.inputs[1];

        // The dummy input utxo we are spending and the pubkey/keysource that will be used to sign it.
        input.witness_utxo = Some(self.input_utxo()?);
        let (pk, key_source) = self.bip32_derivation()?;
        input.bip32_derivations.insert(pk, key_source);
        Ok(psbt)
    }

    /// Provides the actual UTXO that Alice is contributing, this would usually come from the chain.
    fn input_utxo(&self) -> Result<TxOut, Box<dyn std::error::Error>> {
        self.0.input_utxo(Self::PATH)
    }

    fn bip32_derivation(&self) -> Result<(PublicKey, KeySource), Box<dyn std::error::Error>> {
        self.0.bip32_derivation(Self::PATH)
    }
}

impl Default for Bob {
    fn default() -> Self { Self::new() }
}

/// An entity that can take on one of the PSBT roles.
pub struct Entity {
    master: Xpriv,
    secp: Secp256k1<secp256k1::All>,
}

impl Entity {
    /// Creates a new entity with random keys.
    pub fn new(master: Xpriv) -> Self { Self { master, secp: Secp256k1::new() } }

    /// Returns the pubkey for this entity at `derivation_path`.
    fn public_key(
        &self,
        derivation_path: &str,
    ) -> Result<bitcoin::PublicKey, Box<dyn std::error::Error>> {
        let path = derivation_path.parse::<DerivationPath>()?;
        let xpriv = self.master.derive_priv(&self.secp, &path)?;
        let pk = Xpub::from_priv(&self.secp, &xpriv);
        Ok(pk.to_pub().into())
    }

    /// Returns a dummy utxo that we can spend.
    fn input_utxo(&self, derivation_path: &str) -> Result<TxOut, Box<dyn std::error::Error>> {
        // A dummy script_pubkey representing a UTXO that is locked to a pubkey that Alice controls.
        let script_pubkey = ScriptBuf::new_p2wpkh(
            &self.public_key(derivation_path)?.wpubkey_hash().expect("uncompressed key"),
        );
        Ok(TxOut { value: DUMMY_UTXO_AMOUNT, script_pubkey })
    }

    /// Returns the BOP-32 stuff needed to sign an ECDSA input using the [`v2::Psbt`] BIP-32 signing API.
    fn bip32_derivation(
        &self,
        derivation_path: &str,
    ) -> Result<(PublicKey, KeySource), Box<dyn std::error::Error>> {
        let path = derivation_path.parse::<DerivationPath>()?;
        let xpriv = self.master.derive_priv(&self.secp, &path).expect("failed to derive xpriv");
        let fingerprint = xpriv.fingerprint(&self.secp);
        let sk = xpriv.to_priv();
        Ok((sk.public_key(&self.secp), (fingerprint, path)))
    }

    /// Signs any ECDSA inputs for which we have keys.
    pub fn sign_ecdsa(
        &self,
        psbt: Psbt,
        derivation_path: &str,
    ) -> Result<Psbt, Box<dyn std::error::Error>> {
        // Usually we'd have to check this was our input and provide the correct key.
        let path = derivation_path.parse::<DerivationPath>()?;
        let xpriv = self.master.derive_priv(&self.secp, &path)?;

        let inputs_len = psbt.inputs.len();
        let mut signer = Signer::new(psbt)?;
        let sigs = {
            let mut session = signer.session();
            let mut inputs: Vec<SignableInput> = vec![];
            for index in 0..inputs_len {
                match session.assume_checked_input(index) {
                    Ok(signable_input) => inputs.push(signable_input),
                    Err(e) => panic!("Malformed input, cannot be signed: {}", e),
                }
            }
            session.get_all(&inputs, &xpriv, &self.secp)
        };
        let psbt = signer.apply(sigs).unwrap();
        Ok(psbt)
    }
}
