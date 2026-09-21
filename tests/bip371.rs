//! BIP-371 Test Vectors.

#![cfg(all(feature = "std", feature = "base64", feature = "serde", feature = "miniscript"))]

mod vectors;

use vectors::bip371;

mod invalid {
    use super::bip371;

    #[test]
    fn tap_internal_key_key_too_long() {
        bip371("Invalid: PSBT_IN_TAP_INTERNAL_KEY key is too long (incorrectly deserialized as compressed DER)");
    }

    #[test]
    fn tap_key_sig_signature_too_short() {
        bip371("Invalid: PSBT_IN_TAP_KEY_SIG signature is too short");
    }

    #[test]
    fn tap_key_sig_signature_too_long() {
        bip371("Invalid: PSBT_IN_TAP_KEY_SIG signature is too long");
    }

    #[test]
    fn tap_bip32_derivation_key_too_long() {
        bip371("Invalid: PSBT_IN_TAP_BIP32_DERIVATION key is too long (incorrectly deserialized as compressed DER)");
    }

    #[test]
    fn out_tap_internal_key_key_too_long() {
        bip371("Invalid: PSBT_OUT_TAP_INTERNAL_KEY key is too long (incorrectly deserialized as compressed DER)");
    }

    #[test]
    fn out_tap_bip32_derivation_key_too_long() {
        bip371("Invalid: PSBT_OUT_TAP_BIP32_DERIVATION key is too long (incorrectly deserialized as compressed DER)");
    }

    #[test]
    fn tap_script_sig_key_too_long() {
        bip371("Invalid: PSBT_IN_TAP_SCRIPT_SIG key is too long (incorrectly deserialized as compressed DER)");
    }

    #[test]
    fn tap_script_sig_signature_too_long() {
        bip371("Invalid: PSBT_IN_TAP_SCRIPT_SIG signature is too long");
    }

    #[test]
    fn tap_script_sig_signature_too_short() {
        bip371("Invalid: PSBT_IN_TAP_SCRIPT_SIG signature is too short");
    }

    #[test]
    fn tap_leaf_script_control_block_too_long() {
        bip371("Invalid: PSBT_IN_TAP_LEAF_SCRIPT control block is too long");
    }

    #[test]
    fn tap_leaf_script_control_block_too_short() {
        bip371("Invalid: PSBT_IN_TAP_LEAF_SCRIPT control block is too short");
    }
}

mod valid {
    use super::bip371;

    #[test]
    fn one_p2tr_key_only_input_internal_key_derivation() {
        bip371("Valid: one P2TR key only input with internal key and its derivation path");
    }

    #[test]
    fn one_p2tr_key_only_input_internal_key_derivation_1() {
        bip371(
            "Valid: one P2TR key only input with internal key, its derivation path, and signature",
        );
    }

    #[test]
    fn one_p2tr_key_only_output_internal_key_derivation() {
        bip371("Valid: one P2TR key only output with internal key and its derivation path");
    }

    #[test]
    fn one_p2tr_script_path_only_input_dummy_internal() {
        bip371("Valid: one P2TR script path only input with dummy internal key, scripts, derivation paths for keys in the scripts, and merkle root");
    }

    #[test]
    fn one_p2tr_script_path_only_output_dummy_internal() {
        bip371("Valid: one P2TR script path only output with dummy internal key, taproot tree, and script key derivation paths");
    }

    #[test]
    fn one_p2tr_script_path_only_input_dummy_internal_1() {
        bip371("Valid: one P2TR script path only input with dummy internal key, scripts, script key derivation paths, merkle root, and script path signatures");
    }
}
