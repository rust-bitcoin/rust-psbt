//! Test Vectors produced either by LLM audits or fuzzing tools which are not present in the
//! official BIP vectors.

#![cfg(all(feature = "std", feature = "base64", feature = "serde", feature = "miniscript"))]

mod vectors;

use vectors::fuzz;

mod valid {
    use super::fuzz;

    #[test]
    fn psbtv2_empty_out_script() {
        fuzz("Valid: PSBTv2 with present PSBT_OUT_SCRIPT field but empty script.");
    }

    #[test]
    fn strict_signer_with_no_funding_tx_fails() {
        fuzz("Invalid: strict signer with no prevout full tx fails to sign non-p2tr input.");
    }

    #[test]
    fn strict_signer_with_funding_tx_succeeds() {
        fuzz("Valid: strict signer with prevout full tx succeeds to sign non-p2tr input.");
    }
}
