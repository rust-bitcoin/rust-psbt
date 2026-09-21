//! BIP-370 Test Vectors.

#![cfg(all(feature = "std", feature = "base64", feature = "serde", feature = "miniscript"))]

mod vectors;

use vectors::bip370;

mod invalid {
    use super::bip370;

    #[test]
    fn psbtv0_but_global_version_set() { bip370("PSBTv0 but with PSBT_GLOBAL_VERSION set to 2."); }

    #[test]
    fn psbtv0_but_global_tx_version() { bip370("PSBTv0 but with PSBT_GLOBAL_TX_VERSION."); }

    #[test]
    fn psbtv0_but_global_fallback_locktime() {
        bip370("PSBTv0 but with PSBT_GLOBAL_FALLBACK_LOCKTIME.");
    }

    #[test]
    fn psbtv0_but_global_input_count() { bip370("PSBTv0 but with PSBT_GLOBAL_INPUT_COUNT."); }

    #[test]
    fn psbtv0_but_global_output_count() { bip370("PSBTv0 but with PSBT_GLOBAL_OUTPUT_COUNT."); }

    #[test]
    fn psbtv0_but_global_tx_modifiable() { bip370("PSBTv0 but with PSBT_GLOBAL_TX_MODIFIABLE."); }

    #[test]
    fn psbtv0_but_previous_txid() { bip370("PSBTv0 but with PSBT_IN_PREVIOUS_TXID."); }

    #[test]
    fn psbtv0_but_output_index() { bip370("PSBTv0 but with PSBT_IN_OUTPUT_INDEX."); }

    #[test]
    fn psbtv0_but_sequence() { bip370("PSBTv0 but with PSBT_IN_SEQUENCE."); }

    #[test]
    fn psbtv0_but_required_time_locktime() {
        bip370("PSBTv0 but with PSBT_IN_REQUIRED_TIME_LOCKTIME.");
    }

    #[test]
    fn psbtv0_but_required_height_locktime() {
        bip370("PSBTv0 but with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME.");
    }

    #[test]
    fn psbtv0_but_out_amount() { bip370("PSBTv0 but with PSBT_OUT_AMOUNT."); }

    #[test]
    fn psbtv0_but_out_script() { bip370("PSBTv0 but with PSBT_OUT_SCRIPT."); }

    #[test]
    fn psbtv2_missing_global_input_count() { bip370("PSBTv2 missing PSBT_GLOBAL_INPUT_COUNT."); }

    #[test]
    fn psbtv2_missing_global_output_count() { bip370("PSBTv2 missing PSBT_GLOBAL_OUTPUT_COUNT."); }

    #[test]
    fn psbtv2_missing_previous_txid() { bip370("PSBTv2 missing PSBT_IN_PREVIOUS_TXID."); }

    #[test]
    fn psbtv2_missing_output_index() { bip370("PSBTv2 missing PSBT_IN_OUTPUT_INDEX."); }

    #[test]
    fn psbtv2_missing_out_amount() { bip370("PSBTv2 missing PSBT_OUT_AMOUNT."); }

    #[test]
    fn psbtv2_missing_out_script() { bip370("PSBTv2 missing PSBT_OUT_SCRIPT."); }

    #[test]
    fn psbtv2_required_time_locktime_less_than_500000000() {
        bip370("PSBTv2 with PSBT_IN_REQUIRED_TIME_LOCKTIME less than 500000000.");
    }

    #[test]
    fn psbtv2_required_height_locktime_greater_than_equal_500000000() {
        bip370("PSBTv2 with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME greater than or equal to 500000000.");
    }

    #[test]
    fn lock_time_cannot_determined() {
        bip370(
            "Lock time cannot be determined (both time-based and height-based lock times required)",
        );
    }
}

mod valid {
    use super::bip370;

    #[test]
    fn input_output_psbtv2_required_fields_only() {
        bip370("1 input, 2 output PSBTv2, required fields only.");
    }

    #[test]
    fn input_output_updated_psbtv2() { bip370("1 input, 2 output updated PSBTv2."); }

    #[test]
    fn input_output_updated_psbtv2_sequence() {
        bip370("1 input, 2 output updated PSBTv2, with PSBT_IN_SEQUENCE.");
    }

    #[test]
    fn input_output_updated_psbtv2_sequence_all_locktime_fields() {
        bip370("1 input, 2 output updated PSBTv2, with PSBT_IN_SEQUENCE, and all locktime fields");
    }

    #[test]
    fn input_output_updated_psbtv2_inputs_modifiable_flag_global() {
        bip370("1 input, 2 output updated PSBTv2, with Inputs Modifiable Flag (bit 0) of PSBT_GLOBAL_TX_MODIFIABLE set");
    }

    #[test]
    fn input_output_updated_psbtv2_outputs_modifiable_flag_global() {
        bip370("1 input, 2 output updated PSBTv2, with Outputs Modifiable Flag (bit 1) of PSBT_GLOBAL_TX_MODIFIABLE set");
    }

    #[test]
    fn input_output_updated_psbtv2_sighash_single_flag_global() {
        bip370("1 input, 2 output updated PSBTv2, with Has SIGHASH_SINGLE Flag (bit 2) of PSBT_GLOBAL_TX_MODIFIABLE set");
    }

    #[test]
    fn input_output_updated_psbtv2_undefined_flag_global_tx() {
        bip370("1 input, 2 output updated PSBTv2, with an undefined flag (bit 3) of PSBT_GLOBAL_TX_MODIFIABLE set");
    }

    #[test]
    fn input_output_updated_psbtv2_both_inputs_modifiable_flag() {
        bip370("1 input, 2 output updated PSBTv2, with both Inputs Modifiable Flag (bit 0) and Outputs Modifiable Flag (bit 1) of PSBT_GLOBAL_TX_MODIFIABLE set");
    }

    #[test]
    fn input_output_updated_psbtv2_both_inputs_modifiable_flag_1() {
        bip370("1 input, 2 output updated PSBTv2, with both Inputs Modifiable Flag (bit 0) and Has SIGHASH_SINGLE Flag (bit 2) of PSBT_GLOBAL_TX_MODIFIABLE set");
    }

    #[test]
    fn input_output_updated_psbtv2_both_outputs_modifiable_flag() {
        bip370("1 input, 2 output updated PSBTv2, with both Outputs Modifiable Flag (bit 1) and Has SIGHASH_SINGLE FLag (bit 2) of PSBT_GLOBAL_TX_MODIFIABLE set");
    }

    #[test]
    fn input_output_updated_psbtv2_all_defined_global_tx() {
        bip370("1 input, 2 output updated PSBTv2, with all defined PSBT_GLOBAL_TX_MODIFIABLE flags set");
    }

    #[test]
    fn input_output_updated_psbtv2_all_possible_global_tx() {
        bip370("1 input, 2 output updated PSBTv2, with all possible PSBT_GLOBAL_TX_MODIFIABLE flags set");
    }

    #[test]
    fn input_output_updated_psbtv2_all_psbtv2_fields() {
        bip370("1 input, 2 output updated PSBTv2, with all PSBTv2 fields");
    }
}

mod determine_lock_time {
    use super::bip370;

    #[test]
    fn locktimes_specified() { bip370("No locktimes specified"); }

    #[test]
    fn fallback_locktime() { bip370("Fallback locktime of 0"); }

    #[test]
    fn input_required_height_locktime_10000_input_locktime_fields() {
        bip370(
            "Input 1 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 10000, Input 2 has no locktime fields",
        );
    }

    #[test]
    fn input_required_height_locktime_10000_input_required_height() {
        bip370("Input 1 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 10000, Input 2 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 9000");
    }

    #[test]
    fn input_required_height_locktime_10000_input_required_height_1() {
        bip370("Input 1 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 10000, Input 2 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 9000 and PSBT_IN_REQUIRED_TIME_LOCKTIME of 1657048460");
    }

    #[test]
    fn input_required_height_locktime_10000_required_time_locktime() {
        bip370("Input 1 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 10000 and PSBT_IN_REQUIRED_TIME_LOCKTIME of 1657048459, Input 2 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 9000 and PSBT_IN_REQUIRED_TIME_LOCKTIME of 1657048460");
    }

    #[test]
    fn input_required_time_locktime_1657048459_input_required_height() {
        bip370("Input 1 has PSBT_IN_REQUIRED_TIME_LOCKTIME of 1657048459, Input 2 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 9000 and PSBT_IN_REQUIRED_TIME_LOCKTIME of 1657048460");
    }

    #[test]
    fn input_required_height_locktime_10000_required_time_locktime_1() {
        bip370("Input 1 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 10000 and PSBT_IN_REQUIRED_TIME_LOCKTIME of 1657048459, Input 2 has PSBT_IN_REQUIRED_TIME_LOCKTIME of 1657048460");
    }
}
