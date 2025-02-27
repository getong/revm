use super::{g1::extract_g1_input, g2::extract_g2_input};
use crate::bls12_381_const::{
    G1_INPUT_ITEM_LENGTH, G2_INPUT_ITEM_LENGTH, PAIRING_ADDRESS, PAIRING_INPUT_LENGTH,
    PAIRING_PAIRING_MULTIPLIER_BASE, PAIRING_PAIRING_OFFSET_BASE,
};
use crate::{
    u64_to_address, PrecompileError, PrecompileOutput, PrecompileResult, PrecompileWithAddress,
};
use blst::{blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_miller_loop};
use primitives::{Bytes, B256};

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_PAIRING precompile.
pub const PRECOMPILE: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(PAIRING_ADDRESS), pairing);

/// Pairing call expects 384*k (k being a positive integer) bytes as an inputs
/// that is interpreted as byte concatenation of k slices. Each slice has the
/// following structure:
///    * 128 bytes of G1 point encoding
///    * 256 bytes of G2 point encoding
///
/// Each point is expected to be in the subgroup of order q.
/// Output is 32 bytes where first 31 bytes are equal to 0x00 and the last byte
/// is 0x01 if pairing result is equal to the multiplicative identity in a pairing
/// target field and 0x00 otherwise.
///
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-pairing>
pub(super) fn pairing(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let input_len = input.len();
    if input_len == 0 || input_len % PAIRING_INPUT_LENGTH != 0 {
        return Err(PrecompileError::Other(format!(
            "Pairing input length should be multiple of {PAIRING_INPUT_LENGTH}, was {input_len}"
        )));
    }

    let k = input_len / PAIRING_INPUT_LENGTH;
    let required_gas: u64 =
        PAIRING_PAIRING_MULTIPLIER_BASE * k as u64 + PAIRING_PAIRING_OFFSET_BASE;
    if required_gas > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    // Accumulator for the fp12 multiplications of the miller loops.
    let mut acc = blst_fp12::default();
    for i in 0..k {
        // NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
        //
        // So we set the subgroup_check flag to `true`
        let p1_aff = &extract_g1_input(
            &input[i * PAIRING_INPUT_LENGTH..i * PAIRING_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH],
            true,
        )?;

        // NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
        //
        // So we set the subgroup_check flag to `true`
        let p2_aff = &extract_g2_input(
            &input[i * PAIRING_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH
                ..i * PAIRING_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH + G2_INPUT_ITEM_LENGTH],
            true,
        )?;

        if i > 0 {
            // After the first slice (i>0) we use cur_ml to store the current
            // miller loop and accumulate with the previous results using a fp12
            // multiplication.
            let mut cur_ml = blst_fp12::default();
            let mut res = blst_fp12::default();
            // SAFETY: `res`, `acc`, `cur_ml`, `p1_aff` and `p2_aff` are blst values.
            unsafe {
                blst_miller_loop(&mut cur_ml, p2_aff, p1_aff);
                blst_fp12_mul(&mut res, &acc, &cur_ml);
            }
            acc = res;
        } else {
            // On the first slice (i==0) there is no previous results and no need
            // to accumulate.
            // SAFETY: `acc`, `p1_aff` and `p2_aff` are blst values.
            unsafe {
                blst_miller_loop(&mut acc, p2_aff, p1_aff);
            }
        }
    }

    // SAFETY: `ret` and `acc` are blst values.
    let mut ret = blst_fp12::default();
    unsafe {
        blst_final_exp(&mut ret, &acc);
    }

    let mut result: u8 = 0;
    // SAFETY: `ret` is a blst value.
    unsafe {
        if blst_fp12_is_one(&ret) {
            result = 1;
        }
    }
    Ok(PrecompileOutput::new(
        required_gas,
        B256::with_last_byte(result).into(),
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use primitives::hex;

    #[test]
    fn test_pairing() {
        let i1 : Bytes = hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017c9fcf0504e62d3553b2f089b64574150aa5117bd3d2e89a8c1ed59bb7f70fb83215975ef31976e757abf60a75a1d9f0000000000000000000000000000000008f5a53d704298fe0cfc955e020442874fe87d5c729c7126abbdcbed355eef6c8f07277bee6d49d56c4ebaf334848624000000000000000000000000000000001302dcc50c6ce4c28086f8e1b43f9f65543cf598be440123816765ab6bc93f62bceda80045fbcad8598d4f32d03ee8fa000000000000000000000000000000000bbb4eb37628d60b035a3e0c45c0ea8c4abef5a6ddc5625e0560097ef9caab208221062e81cd77ef72162923a1906a40").into();
        let i2 : Bytes = hex!("0000000000000000000000000000000012196c5a43d69224d8713389285f26b98f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f560000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce3032c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fee00000000000000000000000000000000197737f831d4dc7e708475f4ca7ca15284db2f3751fcaac0c17f517f1ddab35e1a37907d7b99b39d6c8d9001cd50e79e000000000000000000000000000000000af1a3f6396f0c983e7c2d42d489a3ae5a3ff0a553d93154f73ac770cd0af7467aa0cef79f10bbd34621b3ec9583a834000000000000000000000000000000001918cb6e448ed69fb906145de3f11455ee0359d030e90d673ce050a360d796de33ccd6a941c49a1414aca1c26f9e699e0000000000000000000000000000000019a915154a13249d784093facc44520e7f3a18410ab2a3093e0b12657788e9419eec25729944f7945e732104939e7a9e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000197737f831d4dc7e708475f4ca7ca15284db2f3751fcaac0c17f517f1ddab35e1a37907d7b99b39d6c8d9001cd50e79e000000000000000000000000000000000af1a3f6396f0c983e7c2d42d489a3ae5a3ff0a553d93154f73ac770cd0af7467aa0cef79f10bbd34621b3ec9583a834000000000000000000000000000000001918cb6e448ed69fb906145de3f11455ee0359d030e90d673ce050a360d796de33ccd6a941c49a1414aca1c26f9e699e0000000000000000000000000000000019a915154a13249d784093facc44520e7f3a18410ab2a3093e0b12657788e9419eec25729944f7945e732104939e7a9e").into();
        let i3 : Bytes = hex!("0000000000000000000000000000000012196c5a43d69224d8713389285f26b98f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f560000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce3032c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fee0000000000000000000000000000000013a3de1d25380c44ca06321151e89ca22210926c1cd4e3c1a9c3aa6c709ab5fdd00f8df19243ce058bc753ccf03424ed000000000000000000000000000000001657dbebf712cbda6f15d1d387c87b3fb9b386d5d754135049728a2a856ba2944c741024131a93c78655fdb7bfe3c80300000000000000000000000000000000068edef3169c58920509ed4e7069229bd8038a45d2ce5773451cc18b396d2838c9539ecb52298a27eebd714afacb907c0000000000000000000000000000000004c5346765a62f2d2e700aadccf747acb3322c250435ce2cf358c08f1e286427cabace052327c4b30135c8482c5c0eb90000000000000000000000000000000008d8c4a16fb9d8800cce987c0eadbb6b3b005c213d44ecb5adeed713bae79d606041406df26169c35df63cf972c94be100000000000000000000000000000000084486ebc81878331aab7d6f53ca3c773fda7b181b56a93e5ee0bfa189afbb7fd7a05c5bea35ec1054c0e1ddc2e2dac2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008d8c4a16fb9d8800cce987c0eadbb6b3b005c213d44ecb5adeed713bae79d606041406df26169c35df63cf972c94be10000000000000000000000000000000011bc8afe71676e6730702a46ef817060249cd06cd82e6981085012ff6d013aa4470ba3a2c71e13ef653e1e223d1ccfe90000000000000000000000000000000013a3de1d25380c44ca06321151e89ca22210926c1cd4e3c1a9c3aa6c709ab5fdd00f8df19243ce058bc753ccf03424ed000000000000000000000000000000001657dbebf712cbda6f15d1d387c87b3fb9b386d5d754135049728a2a856ba2944c741024131a93c78655fdb7bfe3c80300000000000000000000000000000000137232f722e38e084611ba67d2e28a3b8c73c13f20b6bb4c22141115bd43cdeb555861335f2a75d7cb418eb505341a2f00000000000000000000000000000000153bdd82d3d9b76d1cab9d087654652ab1451f5fef4f449273d81211d88891fc53f131f98e2c3b4cb8c937b7d3a39bf20000000000000000000000000000000008d8c4a16fb9d8800cce987c0eadbb6b3b005c213d44ecb5adeed713bae79d606041406df26169c35df63cf972c94be100000000000000000000000000000000084486ebc81878331aab7d6f53ca3c773fda7b181b56a93e5ee0bfa189afbb7fd7a05c5bea35ec1054c0e1ddc2e2dac20000000000000000000000000000000013a3de1d25380c44ca06321151e89ca22210926c1cd4e3c1a9c3aa6c709ab5fdd00f8df19243ce058bc753ccf03424ed000000000000000000000000000000001657dbebf712cbda6f15d1d387c87b3fb9b386d5d754135049728a2a856ba2944c741024131a93c78655fdb7bfe3c80300000000000000000000000000000000137232f722e38e084611ba67d2e28a3b8c73c13f20b6bb4c22141115bd43cdeb555861335f2a75d7cb418eb505341a2f00000000000000000000000000000000153bdd82d3d9b76d1cab9d087654652ab1451f5fef4f449273d81211d88891fc53f131f98e2c3b4cb8c937b7d3a39bf2").into();

        let g1 = 70300;
        let g2 = 102900;
        let g3 = 168100;

        let expected = Bytes::from_static(&hex!(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));

        assert_eq!(
            pairing(&i1, g1),
            Ok(PrecompileOutput::new(g1, expected.clone()))
        );
        assert_eq!(
            pairing(&i2, g2),
            Ok(PrecompileOutput::new(g2, expected.clone()))
        );
        assert_eq!(pairing(&i3, g3), Ok(PrecompileOutput::new(g3, expected)));
    }
}
