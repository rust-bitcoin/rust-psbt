//! BIP-174 test vectors.
//!
//! Each test case is keyed by its canonical description from bip174.json.

#![cfg(all(feature = "std", feature = "base64", feature = "serde", feature = "miniscript"))]

mod vectors;

use vectors::bip174;

mod invalid {
    use super::bip174;

    #[test]
    fn network_transaction() { bip174("Invalid: network transaction, not PSBT format"); }

    #[test]
    fn missing_outputs() { bip174("Invalid: missing outputs in PSBT"); }

    #[test]
    fn unsigned_transaction_contains_input_non_empty_scriptsig() {
        bip174("Invalid: the unsigned transaction contains an input with a non empty scriptSig");
    }

    #[test]
    fn missing_unsigned_tx_where_inputs_outputs_provided() {
        bip174("Invalid: missing unsigned tx on a PSBT where inputs and outputs are provided");
    }

    #[test]
    fn duplicated_keys_one_input() { bip174("Invalid: duplicated keys in one PSBT input"); }

    #[test]
    fn global_transaction() { bip174("Invalid: invalid global transaction in PSBT"); }

    #[test]
    fn input_witness_utxo() { bip174("Invalid: invalid input witness utxo in PSBT"); }

    #[test]
    fn pubkey_length_input_partial_signature() {
        bip174("Invalid: invalid pubkey length on PSBT input partial signature");
    }

    #[test]
    fn redeemscript() { bip174("Invalid: invalid redeemscript in PSBT"); }

    #[test]
    fn witnessscript() { bip174("Invalid: invalid witnessscript in PSBT"); }

    #[test]
    fn pubkey_input_32_derivation_paths() {
        bip174("Invalid: invalid pubkey in PSBT input BIP 32 derivation paths");
    }

    #[test]
    fn non_witness_utxo_input() { bip174("Invalid: invalid non-witness utxo in PSBT input"); }

    #[test]
    fn final_scriptsig() { bip174("Invalid: invalid final scriptSig in PSBT"); }

    #[test]
    fn final_script_witness() { bip174("Invalid: invalid final script witness in PSBT"); }

    #[test]
    fn public_key_output_32_derivation_paths() {
        bip174("Invalid: invalid public key in PSBT output BIP 32 derivation paths");
    }

    #[test]
    fn sighash_type_input() { bip174("Invalid: invalid SIGHASH type in PSBT input"); }

    #[test]
    fn output_redeemscript() { bip174("Invalid: invalid output redeemScript in PSBT"); }

    #[test]
    fn witnessscript_output() { bip174("Invalid: invalid witnessScript in PSBT output"); }

    #[test]
    fn unsigned_tx_serialized_witness_serialization_format() {
        bip174("Invalid: unsigned tx serialized with witness serialization format in PSBT");
    }

    #[test]
    fn valuesize_length_does_match_valuelen_size() {
        bip174("Invalid: <valuesize> length does not match <valuelen> size in PSBT");
    }

    #[test]
    fn witness_utxo_provided_non_witness_input() {
        bip174("Invalid: a Witness UTXO is provided for a non-witness input");
    }

    #[test]
    fn redeemscript_non_witness_utxo_does_match_scriptpubkey() {
        bip174("Invalid: redeemScript with non-witness UTXO does not match the scriptPubKey");
    }

    #[test]
    fn redeemscript_witness_utxo_does_not_match_scriptpubkey() {
        bip174("Invalid: redeemScript with witness UTXO does not match the scriptPubKey");
    }

    #[test]
    fn witnessscript_witness_utxo_does_match_redeemscript() {
        bip174("Invalid: witnessScript with witness UTXO does not match the redeemScript");
    }
}

mod valid {
    use super::bip174;

    #[test]
    fn one_p2pkh_input_outputs() { bip174("Valid: one P2PKH input and no outputs in PSBT"); }

    #[test]
    fn one_signed_finalized_p2pkh_input_one_p2sh_p2wpkh() {
        bip174("Valid: PSBT with one signed and finalized P2PKH input and one P2SH-P2WPKH input. Outputs are empty");
    }

    #[test]
    fn one_p2pkh_input_non_final_scriptsig_sighash_type() {
        bip174("Valid: PSBT with one P2PKH input with a non-final scriptSig and sighash type set. Outputs are empty");
    }

    #[test]
    fn one_p2pkh_input_one_p2sh_p2wpkh_input_both() {
        bip174("Valid: PSBT with one P2PKH input and one P2SH-P2WPKH input both with non-final scriptSigs. P2SH-P2WPKH input's redeemScript is available. Outputs filled.");
    }

    #[test]
    fn one_p2sh_p2wsh_input_multisig_redeemscript_witnessscript_keypaths() {
        bip174("Valid: PSBT with one P2SH-P2WSH input of a 2-of-2 multisig. redeemScript, witnessScript, and keypaths are available. Contains one signature.");
    }

    #[test]
    fn one_p2wsh_input_multisig_witnessscript_keypaths_global_xpubs() {
        bip174("Valid: PSBT with one P2WSH input of a 2-of-2 multisig. witnessScript, keypaths, and global xpubs are available. Contains no signatures. Outputs filled.");
    }

    #[test]
    fn unknown_types_inputs() { bip174("Valid: PSBT with unknown types in the inputs."); }

    #[test]
    fn global_xpub() { bip174("Valid: PSBT with `PSBT_GLOBAL_XPUB`."); }

    #[test]
    fn global_unsigned_tx_inputs_nor_outputs() {
        bip174("Valid: PSBT with global unsigned tx and no inputs nor outputs");
    }

    #[test]
    fn no_inputs() { bip174("Valid: PSBT with no inputs"); }

    #[test]
    fn combine_with_unknown_key_value_pairs() {
        bip174("Valid: taking as input the PSBTs with unknown key-value pairs, a Combiner which orders keys lexicographically combines them into a single PSBT");
    }
}

mod workflow {
    use super::bip174;

    #[test]
    fn creator_takes_given_inputs_outputs() {
        bip174("Workflow A (step 1): the Creator takes the given inputs and outputs and produces the PSBT");
    }

    #[test]
    fn updater_takes_key_witness_material() {
        bip174("Workflow A (step 2): with the PSBT produced in step 1 of Workflow A, the Updater takes the key and witness material and updates the PSBT");
    }

    #[test]
    fn updater_adds_sighash_flag() {
        bip174("Workflow A (step 3): with the PSBT produced in step 2 of Workflow A, the Updater adds the sighash flag to the PSBT");
    }

    #[test]
    fn signer_which_supports_sighash_all() {
        bip174("Workflow A (step 4): with the PSBT produced in step 3 of Workflow A, a Signer which supports SIGHASH_ALL for P2PKH and P2WPKH spends and uses RFC6979 for nonce generation, adds the first partial signature of the second input of the PSBT");
    }

    #[test]
    fn signer_adds_second_partial_signature() {
        bip174("Workflow A (step 5): with the PSBT produced in step 4 of Workflow A, a Signer adds the second partial signature of the second input of the PSBT");
    }

    #[test]
    fn combiner_combines_them() {
        bip174("Workflow A (step 6): with the PSBTs produced in step 4 and step 5 of Workflow A, a Combiner combines them into a single PSBT");
    }

    #[test]
    fn finalizer_finalizes_second_input() {
        bip174("Workflow A (step 7): with the PSBT produced in step 6 of Workflow A, an Input Finalizer finalizes the second input of the PSBT");
    }

    #[test]
    fn extractor_extracts_bitcoin_transaction() {
        bip174("Workflow A (step 8): with the PSBT produced in step 7 of Workflow A, a Transaction Extractor extracts a bitcoin transaction");
    }
}
