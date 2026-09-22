//! [BIP-375 Test Vectors](https://github.com/bitcoin/bips/blob/master/bip-0375/bip375_test_vectors.json).

#![cfg(all(
    feature = "std",
    feature = "base64",
    feature = "serde",
    feature = "miniscript",
    feature = "silent-payments"
))]

mod vectors;

use vectors::bip375;

mod invalid {
    use super::bip375;

    #[test]
    fn structure_missing_sp_v0_info_when_label_set() {
        bip375("Invalid: psbt structure: missing PSBT_OUT_SP_V0_INFO field when PSBT_OUT_SP_V0_LABEL set");
    }

    #[test]
    fn structure_incorrect_byte_length_out_sp_v0_info() {
        bip375("Invalid: psbt structure: incorrect byte length for PSBT_OUT_SP_V0_INFO field");
    }

    #[test]
    fn structure_incorrect_byte_length_sp_ecdh_share_field() {
        bip375("Invalid: psbt structure: incorrect byte length for PSBT_IN_SP_ECDH_SHARE field");
    }

    #[test]
    fn structure_incorrect_byte_length_sp_dleq_field() {
        bip375("Invalid: psbt structure: incorrect byte length for PSBT_IN_SP_DLEQ field");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn structure_tx_modifiable_non_zero_for_sp_output() {
        bip375("Invalid: psbt structure: PSBT_GLOBAL_TX_MODIFIABLE field is non-zero when PSBT_OUT_SCRIPT set for sp output");
    }

    #[test]
    fn structure_missing_out_script_for_non_sp_output() {
        bip375("Invalid: psbt structure: missing PSBT_OUT_SCRIPT field when sending to non-sp output");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn ecdh_coverage_only_one_ineligible_p2sh_multisig_input() {
        bip375("Invalid: ecdh coverage: only one ineligible P2SH multisig input when PSBT_OUT_SCRIPT set for sp output");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn ecdh_coverage_missing_ecdh_share_for_input_0() {
        bip375("Invalid: ecdh coverage: missing PSBT_IN_SP_ECDH_SHARE field for input 0 when PSBT_OUT_SCRIPT set for sp output");
    }

    #[test]
    fn ecdh_coverage_missing_dleq_when_ecdh_share_set() {
        bip375(
            "Invalid: ecdh coverage: missing PSBT_IN_SP_DLEQ field for input when PSBT_IN_SP_ECDH_SHARE set",
        );
    }

    #[test]
    fn ecdh_coverage_missing_global_dleq_when_ecdh_share_set() {
        bip375(
            "Invalid: ecdh coverage: missing PSBT_GLOBAL_SP_DLEQ field when PSBT_GLOBAL_SP_ECDH_SHARE set",
        );
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn ecdh_coverage_invalid_proof_sp_dleq_field() {
        bip375("Invalid: ecdh coverage: invalid proof in PSBT_IN_SP_DLEQ field");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn ecdh_coverage_invalid_proof_global_sp_dleq_field() {
        bip375("Invalid: ecdh coverage: invalid proof in PSBT_GLOBAL_SP_DLEQ field");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn ecdh_coverage_missing_bip32_derivation_when_dleq_set() {
        bip375("Invalid: ecdh coverage: missing PSBT_IN_BIP32_DERIVATION field for input when PSBT_IN_SP_DLEQ set");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn ecdh_coverage_output_missing_ecdh_share_scan_key() {
        bip375("Invalid: ecdh coverage: output 1 missing ECDH share for scan key with one input / three sp outputs (different scan keys)");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn ecdh_coverage_input_missing_ecdh_share_output_two() {
        bip375("Invalid: ecdh coverage: input 1 missing ECDH share for output 1 with two inputs / two sp outputs (different scan keys)");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn ecdh_coverage_input_missing_ecdh_share_scan_key() {
        bip375("Invalid: ecdh coverage: input 1 missing ECDH share for scan key with two inputs / one sp output");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn input_eligibility_segwit_version_greater_than_transaction_inputs() {
        bip375(
            "Invalid: input eligibility: segwit version greater than 1 in transaction inputs with sp output",
        );
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn input_eligibility_non_sighash_all_signature_input_sp() {
        bip375("Invalid: input eligibility: non-SIGHASH_ALL signature on input with sp output");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn output_scripts_nums_internal_key_cannot_derive_sp() {
        bip375("Invalid: output scripts: P2TR input with NUMS internal key cannot derive sp output");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn output_scripts_out_script_does_not_match_derived_sp() {
        bip375("Invalid: output scripts: PSBT_OUT_SCRIPT does not match derived sp output");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn output_scripts_two_sp_outputs_sorted_lexicographically_spend() {
        bip375("Invalid: output scripts: two sp outputs (same scan / different spend keys) not sorted lexicographically by spend key");
    }

    // TODO: Validation not yet implemented.
    #[ignore]
    #[test]
    fn output_scripts_values_assigned_wrong_output_indices_three() {
        bip375("Invalid: output scripts: k values assigned to wrong output indices with three sp outputs (same scan / spend keys)");
    }
}

mod valid {
    use super::bip375;

    #[test]
    fn can_finalize_one_p2pkh_input_single_signer() {
        bip375("Valid: can finalize: one P2PKH input single-signer");
    }

    #[test]
    fn can_finalize_two_inputs_single_signer_using_global() {
        bip375("Valid: can finalize: two inputs single-signer using global ECDH share");
    }

    #[test]
    fn can_finalize_two_inputs_single_signer_using_per() {
        bip375("Valid: can finalize: two inputs single-signer using per-input ECDH shares");
    }

    #[test]
    fn can_finalize_two_inputs_two_sp_outputs_mixed() {
        bip375(
            "Valid: can finalize: two inputs / two sp outputs with mixed global and per-input ECDH shares",
        );
    }

    #[test]
    fn can_finalize_one_input_one_sp_output_both() {
        bip375(
            "Valid: can finalize: one input / one sp output with both global and per-input ECDH shares",
        );
    }

    #[test]
    fn can_finalize_three_sp_outputs_multiple_global_ecdh() {
        bip375(
            "Valid: can finalize: three sp outputs (different scan keys) with multiple global ECDH shares",
        );
    }

    #[test]
    fn can_finalize_one_p2wpkh_input_two_mixed_outputs() {
        bip375("Valid: can finalize: one P2WPKH input / two mixed outputs - labeled sp output and BIP 32 change");
    }

    #[test]
    fn can_finalize_one_input_two_sp_outputs() {
        bip375("Valid: can finalize: one input / two sp outputs - output 0 has no label / output 1 uses label=0 convention for sp change");
    }

    #[test]
    fn can_finalize_two_sp_outputs_labeled() {
        bip375("Valid: can finalize: two sp outputs - output 0 uses label=3 / output 1 uses label=1");
    }

    #[test]
    fn can_finalize_two_inputs_using_per_input_ecdh() {
        bip375("Valid: can finalize: two inputs using per-input ECDH shares - only eligible inputs contribute shares (P2SH excluded)");
    }

    #[test]
    fn can_finalize_two_inputs_using_global_ecdh_share() {
        bip375("Valid: can finalize: two inputs using global ECDH share - only eligible inputs contribute shares (P2SH excluded)");
    }

    #[test]
    fn can_finalize_two_mixed_input_types_only_eligible() {
        bip375("Valid: can finalize: two mixed input types - only eligible inputs contribute ECDH shares (NUMS internal key excluded)");
    }

    #[test]
    fn can_finalize_three_sp_outputs_each_output_distinct() {
        bip375("Valid: can finalize: three sp outputs (same scan key) - each output has distinct k value");
    }

    #[test]
    fn can_finalize_three_sp_outputs_two_regular_outputs() {
        bip375("Valid: can finalize: three sp outputs (same scan key) / two regular outputs - k values assigned independently of output index");
    }

    #[test]
    fn progress_two_p2tr_inputs_neither_signed() {
        bip375("Valid: in progress: two P2TR inputs, neither is signed");
    }

    #[test]
    fn progress_one_p2tr_input_one_sp_output_ecdh() {
        bip375("Valid: in progress: one P2TR input / one sp output with no ECDH shares when PSBT_OUT_SCRIPT field is not set");
    }

    #[test]
    fn progress_two_inputs_one_sp_output_missing_ecdh() {
        bip375("Valid: in progress: two inputs / one sp output, input 1 missing ECDH share when PSBT_OUT_SCRIPT field is not set");
    }

    #[test]
    fn progress_one_input_two_sp_outputs_missing_ecdh() {
        bip375("Valid: in progress: one input / two sp outputs, input 0 missing ECDH share for output 0 when PSBT_OUT_SCRIPT field is not set");
    }

    #[test]
    fn progress_large_nine_mixed_inputs_six_outputs_some() {
        bip375("Valid: in progress: large PSBT with nine mixed inputs / six outputs - some inputs signed");
    }
}
