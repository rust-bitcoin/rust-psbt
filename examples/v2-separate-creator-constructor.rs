//! PSBT v2 - Creator a PSBT and hand it around to various different entities to add inputs and outputs.

use psbt_v2::bitcoin::hashes::Hash as _;
use psbt_v2::bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
use psbt_v2::{
    Constructor, Creator, InputBuilder, InputsOnlyModifiable, OutputBuilder, OutputsOnlyModifiable,
    Psbt,
};

fn main() -> anyhow::Result<()> {
    // Create the PSBT.
    let created = Creator::new().inputs_modifiable().outputs_modifiable().psbt();

    let ser = created.serialize();

    // The first constructor entity receives the PSBT and adds an input.
    let psbt = Psbt::deserialize(&ser)?;
    let in_0 = dummy_out_point();
    let ser = Constructor::<InputsOnlyModifiable>::new(psbt)?
        .input(InputBuilder::new(&in_0).build())
        .psbt()
        .expect("valid lock time combination")
        .serialize();

    // The second constructor entity receives the PSBT with one input and adds a second input.
    let psbt = Psbt::deserialize(&ser)?;
    let in_1 = dummy_out_point();
    let ser = Constructor::<InputsOnlyModifiable>::new(psbt)?
        .input(InputBuilder::new(&in_1).build())
        .no_more_inputs()
        .psbt()
        .expect("valid lock time combination")
        .serialize();

    // The third constructor entity receives the PSBT with inputs and adds an output.
    let psbt = Psbt::deserialize(&ser)?;
    let output = dummy_tx_out();
    let ser = Constructor::<OutputsOnlyModifiable>::new(psbt)?
        .output(OutputBuilder::new(output).build())?
        .no_more_outputs()
        .psbt()
        .expect("valid lock time combination")
        .serialize();

    // The PSBT is now ready for handling with the updater role.
    let _updatable_psbt = Psbt::deserialize(&ser)?;

    Ok(())
}

/// A dummy `OutPoint`, this would usually be the unspent transaction that we are spending.
fn dummy_out_point() -> OutPoint {
    let txid = Txid::hash(b"some arbitrary bytes");
    let vout = 0x15;
    OutPoint { txid, vout }
}

/// A dummy `TxOut`, this would usually be the output we are creating with this transaction.
fn dummy_tx_out() -> TxOut {
    // Arbitrary script, may not even be a valid scriptPubkey.
    let script = ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        .expect("failed to parse script form hex");
    let value = Amount::from_sat(123_456_789);
    TxOut { value, script_pubkey: script }
}
