use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;

const VERSION: u8 = 2;
const MAX_PLAINTEXT_SIZE: usize = 65535;

#[derive(thiserror::Error, Debug)]
pub enum EncryptError {
    #[error("plaintext must be between 1 and 65535 bytes")]
    InvalidPlaintextSize,
}

pub fn encrypt(
    plaintext: &str,
    conversation_key: &[u8; 32],
    custom_nonce: Option<[u8; 32]>,
) -> Result<String, EncryptError> {
    let nonce = custom_nonce.unwrap_or_else(|| crate::SecretKey::generate().0);
    let (cc20key, cc20nonce, hmac_key) = message_keys(conversation_key, nonce);

    let plain = plaintext.as_bytes();
    let size = plain.len();
    if size == 0 || size > MAX_PLAINTEXT_SIZE {
        return Err(EncryptError::InvalidPlaintextSize);
    }

    let padded_len = calc_padded_len(size);
    let mut padded = Vec::with_capacity(2 + padded_len);
    padded.extend_from_slice(&(size as u16).to_be_bytes());
    padded.extend_from_slice(plain);
    padded.resize(2 + padded_len, 0);

    let mut cipher = chacha20::ChaCha20::new(&cc20key.into(), &cc20nonce.into());
    cipher.apply_keystream(&mut padded);

    let mac = sha256_hmac(&hmac_key, &padded, nonce);

    let mut concat = Vec::with_capacity(1 + 32 + padded.len() + 32);
    concat.push(VERSION);
    concat.extend_from_slice(&nonce);
    concat.extend_from_slice(&padded);
    concat.extend_from_slice(&mac);

    Ok(base64::engine::general_purpose::STANDARD.encode(&concat))
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum DecryptError {
    #[error("invalid payload length")]
    InvalidPayloadLength,

    #[error("unknown version")]
    UnknownVersion,

    #[error("invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("invalid data length")]
    InvalidDataLength,

    #[error("invalid hmac")]
    InvalidHmac,

    #[error("invalid padding")]
    InvalidPadding,

    #[error("plaintext is not valid utf-8")]
    InvalidUtf8,
}

pub fn decrypt(
    b64_ciphertext_wrapped: &str,
    conversation_key: &[u8; 32],
) -> Result<String, DecryptError> {
    let c_len = b64_ciphertext_wrapped.len();
    if !(132..=87472).contains(&c_len) {
        return Err(DecryptError::InvalidPayloadLength);
    }
    if b64_ciphertext_wrapped.starts_with('#') {
        return Err(DecryptError::UnknownVersion);
    }

    let decoded = base64::engine::general_purpose::STANDARD.decode(b64_ciphertext_wrapped)?;

    if decoded[0] != VERSION {
        return Err(DecryptError::UnknownVersion);
    }

    let d_len = decoded.len();
    if !(99..=65603).contains(&d_len) {
        return Err(DecryptError::InvalidDataLength);
    }

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&decoded[1..33]);
    let ciphertext = &decoded[33..d_len - 32];
    let given_mac = &decoded[d_len - 32..];

    let (cc20key, cc20nonce, hmac_key) = message_keys(conversation_key, nonce);

    // constant-time comparison
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&hmac_key)
        .expect("hmac can take key of any size so this never fails");
    mac.update(&nonce);
    mac.update(ciphertext);
    mac.verify_slice(given_mac)
        .map_err(|_| DecryptError::InvalidHmac)?;

    let mut padded = ciphertext.to_vec();
    let mut cipher = chacha20::ChaCha20::new(&cc20key.into(), &cc20nonce.into());
    cipher.apply_keystream(&mut padded);

    let unpadded_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if unpadded_len == 0
        || unpadded_len > MAX_PLAINTEXT_SIZE
        || padded.len() != 2 + calc_padded_len(unpadded_len)
    {
        return Err(DecryptError::InvalidPadding);
    }

    let unpadded = &padded[2..2 + unpadded_len];
    if unpadded.is_empty() || unpadded.len() != unpadded_len {
        return Err(DecryptError::InvalidPadding);
    }

    String::from_utf8(unpadded.to_vec()).map_err(|_| DecryptError::InvalidUtf8)
}

pub fn generate_conversation_key(pubkey: &crate::PubKey, sk: &crate::SecretKey) -> [u8; 32] {
    let shared_secret =
        secp256k1::ecdh::shared_secret_point(&pubkey.to_ecdsa_key(), &sk.to_ecdsa_key());

    hkdf_extract("nip44-v2".as_bytes(), &shared_secret[0..32])
}

fn message_keys(conversation_key: &[u8; 32], nonce: [u8; 32]) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let output = hkdf_expand_into(conversation_key, &nonce, 3);

    let mut cc20key = [0u8; 32];
    let mut cc20nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];

    cc20key.copy_from_slice(&output[0..32]);
    cc20nonce.copy_from_slice(&output[32..44]);
    hmac_key.copy_from_slice(&output[44..76]);

    (cc20key, cc20nonce, hmac_key)
}

#[inline]
fn sha256_hmac(key: &[u8], ciphertext: &[u8], nonce: [u8; 32]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
        .expect("hmac can take key of any size so this never fails");
    mac.update(&nonce);
    mac.update(ciphertext);
    mac.finalize().into_bytes().to_vec()
}

fn calc_padded_len(s_len: usize) -> usize {
    if s_len <= 32 {
        return 32;
    }
    let next_power = (s_len - 1).next_power_of_two();
    let chunk = 32.max(next_power / 8);
    chunk * ((s_len - 1) / chunk + 1)
}

#[inline]
fn hkdf_extract(salt: &[u8], input_key: &[u8]) -> [u8; 32] {
    let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(salt)
        .expect("hmac can take keys of any size so this never fails");
    hmac.update(input_key);
    hmac.finalize().into_bytes().into()
}

fn hkdf_expand_into(pseudorandomkey: &[u8], info: &[u8], iterations: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(iterations * 32);

    let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(pseudorandomkey)
        .expect("hmac can take keys of any size so this never fails");

    for counter in (1u8..).take(iterations) {
        hmac.update(info);
        hmac.update(&[counter]);

        let val = hmac.finalize().into_bytes();

        // prepare next iteration
        hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(pseudorandomkey)
            .expect("hmac can take keys of any size so this never fails");
        hmac.update(&val);

        // save this result
        output.extend_from_slice(&val);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use sha2::Digest;

    fn assert_crypt_sec(
        sk1_hex: &str,
        sk2_hex: &str,
        conversation_key_hex: &str,
        salt_hex: &str,
        plaintext: &str,
        expected: &str,
    ) {
        let pub2 = sk2_hex.parse::<SecretKey>().unwrap().pubkey();
        let mut conversation_key: [u8; 32] = Default::default();
        lowercase_hex::decode_to_slice(conversation_key_hex, &mut conversation_key[0..32]).unwrap();
        let mut salt: [u8; 32] = Default::default();
        lowercase_hex::decode_to_slice(salt_hex, &mut salt[0..32]).unwrap();

        assert_conversation_key_generation_pub(sk1_hex, &pub2.to_hex(), conversation_key_hex);

        let actual = encrypt(plaintext, &conversation_key, Some(salt)).unwrap();
        assert_eq!(actual, expected, "wrong encryption");

        let decrypted = decrypt(expected, &conversation_key).unwrap();
        assert_eq!(decrypted, plaintext, "wrong decryption");
    }

    fn assert_decrypt_fail(
        conversation_key_hex: &str,
        ciphertext: &str,
        expected_error: DecryptError,
    ) {
        let mut conversation_key: [u8; 32] = Default::default();
        lowercase_hex::decode_to_slice(conversation_key_hex, &mut conversation_key[0..32]).unwrap();
        let result = decrypt(ciphertext, &conversation_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), expected_error);
    }

    fn assert_conversation_key_generation_pub(
        sec_hex: &str,
        pub_hex: &str,
        conversation_key_hex: &str,
    ) {
        let mut expected_conversation_key: [u8; 32] = Default::default();
        lowercase_hex::decode_to_slice(conversation_key_hex, &mut expected_conversation_key[0..32])
            .unwrap();

        let sk: SecretKey = sec_hex.parse().unwrap();
        let pk: PubKey = pub_hex.parse().unwrap();
        let actual_conversation_key = generate_conversation_key(&pk, &sk);

        assert_eq!(
            actual_conversation_key, expected_conversation_key,
            "wrong conversation key"
        );
    }

    fn assert_message_key_generation(
        conversation_key_hex: &str,
        salt_hex: &str,
        chacha_key_hex: &str,
        chacha_salt_hex: &str,
        hmac_key_hex: &str,
    ) {
        let mut expected_conversation_key: [u8; 32] = Default::default();
        lowercase_hex::decode_to_slice(conversation_key_hex, &mut expected_conversation_key[0..32])
            .unwrap();

        let mut salt: [u8; 32] = Default::default();
        lowercase_hex::decode_to_slice(salt_hex, &mut salt[0..32]).unwrap();

        let expected_chacha_key = lowercase_hex::decode(chacha_key_hex).unwrap();
        let expected_chacha_nonce = lowercase_hex::decode(chacha_salt_hex).unwrap();
        let expected_hmac_key = lowercase_hex::decode(hmac_key_hex).unwrap();

        let (actual_chacha_key, actual_chacha_nonce, actual_hmac_key) =
            message_keys(&expected_conversation_key, salt);

        assert_eq!(expected_chacha_key, actual_chacha_key, "wrong chacha key");
        assert_eq!(
            expected_chacha_nonce, actual_chacha_nonce,
            "wrong chacha nonce"
        );
        assert_eq!(expected_hmac_key, actual_hmac_key, "wrong hmac key");
    }

    fn assert_crypt_long(
        conversation_key_hex: &str,
        salt_hex: &str,
        pattern: &str,
        repeat: usize,
        plaintext_sha256_hex: &str,
        payload_sha256_hex: &str,
    ) {
        let mut conversation_key: [u8; 32] = Default::default();
        lowercase_hex::decode_to_slice(conversation_key_hex, &mut conversation_key[0..32]).unwrap();

        let mut salt: [u8; 32] = Default::default();
        lowercase_hex::decode_to_slice(salt_hex, &mut salt[0..32]).unwrap();

        let plaintext = pattern.repeat(repeat);
        let mut h = sha2::Sha256::new();
        h.update(plaintext.as_bytes());
        let actual_plaintext_sha256 = lowercase_hex::encode(h.finalize());
        assert_eq!(
            plaintext_sha256_hex, actual_plaintext_sha256,
            "invalid plaintext sha256 hash"
        );

        let actual_payload = encrypt(&plaintext, &conversation_key, Some(salt)).unwrap();
        let mut h = sha2::Sha256::new();
        h.update(actual_payload.as_bytes());
        let actual_payload_sha256 = lowercase_hex::encode(h.finalize());
        assert_eq!(
            payload_sha256_hex, actual_payload_sha256,
            "invalid payload sha256 hash"
        );
    }

    #[test]
    fn test_crypt_sec_001() {
        assert_crypt_sec(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "a",
            "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb",
        );
    }

    #[test]
    fn test_crypt_sec_002() {
        assert_crypt_sec(
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
            "f00000000000000000000000000000f00000000000000000000000000000000f",
            "🍕🫃",
            "AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8nDITO+QfaQ61+KbWQIOO2Yj",
        );
    }

    #[test]
    fn test_crypt_sec_003() {
        assert_crypt_sec(
            "5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a",
            "4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d",
            "3e2b52a63be47d34fe0a80e34e73d436d6963bc8f39827f327057a9986c20a45",
            "b635236c42db20f021bb8d1cdff5ca75dd1a0cc72ea742ad750f33010b24f73b",
            "表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀",
            "ArY1I2xC2yDwIbuNHN/1ynXdGgzHLqdCrXUPMwELJPc7s7JqlCMJBAIIjfkpHReBPXeoMCyuClwgbT419jUWU1PwaNl4FEQYKCDKVJz+97Mp3K+Q2YGa77B6gpxB/lr1QgoqpDf7wDVrDmOqGoiPjWDqy8KzLueKDcm9BVP8xeTJIxs=",
        );
    }

    #[test]
    fn test_crypt_sec_004() {
        assert_crypt_sec(
            "8f40e50a84a7462e2b8d24c28898ef1f23359fff50d8c509e6fb7ce06e142f9c",
            "b9b0a1e9cc20100c5faa3bbe2777303d25950616c4c6a3fa2e3e046f936ec2ba",
            "d5a2f879123145a4b291d767428870f5a8d9e5007193321795b40183d4ab8c2b",
            "b20989adc3ddc41cd2c435952c0d59a91315d8c5218d5040573fc3749543acaf",
            "ability🤝的 ȺȾ",
            "ArIJia3D3cQc0sQ1lSwNWakTFdjFIY1QQFc/w3SVQ6yvbG2S0x4Yu86QGwPTy7mP3961I1XqB6SFFTzqDZZavhxoWMj7mEVGMQIsh2RLWI5EYQaQDIePSnXPlzf7CIt+voTD",
        );
    }

    #[test]
    fn test_crypt_sec_005() {
        assert_crypt_sec(
            "875adb475056aec0b4809bd2db9aa00cff53a649e7b59d8edcbf4e6330b0995c",
            "9c05781112d5b0a2a7148a222e50e0bd891d6b60c5483f03456e982185944aae",
            "3b15c977e20bfe4b8482991274635edd94f366595b1a3d2993515705ca3cedb8",
            "8d4442713eb9d4791175cb040d98d6fc5be8864d6ec2f89cf0895a2b2b72d1b1",
            "pepper👀їжак",
            "Ao1EQnE+udR5EXXLBA2Y1vxb6IZNbsL4nPCJWisrctGxY3AduCS+jTUgAAnfvKafkmpy15+i9YMwCdccisRa8SvzW671T2JO4LFSPX31K4kYUKelSAdSPwe9NwO6LhOsnoJ+",
        );
    }

    #[test]
    fn test_crypt_sec_006() {
        assert_crypt_sec(
            "eba1687cab6a3101bfc68fd70f214aa4cc059e9ec1b79fdb9ad0a0a4e259829f",
            "dff20d262bef9dfd94666548f556393085e6ea421c8af86e9d333fa8747e94b3",
            "4f1538411098cf11c8af216836444787c462d47f97287f46cf7edb2c4915b8a5",
            "2180b52ae645fcf9f5080d81b1f0b5d6f2cd77ff3c986882bb549158462f3407",
            "( ͡° ͜ʖ ͡°)",
            "AiGAtSrmRfz59QgNgbHwtdbyzXf/PJhogrtUkVhGLzQHv4qhKQwnFQ54OjVMgqCea/Vj0YqBSdhqNR777TJ4zIUk7R0fnizp6l1zwgzWv7+ee6u+0/89KIjY5q1wu6inyuiv",
        );
    }

    #[test]
    fn test_crypt_sec_007() {
        assert_crypt_sec(
            "d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
            "b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
            "75fe686d21a035f0c7cd70da64ba307936e5ca0b20710496a6b6b5f573377bdd",
            "e4cd5f7ce4eea024bc71b17ad456a986a74ac426c2c62b0a15eb5c5c8f888b68",
            "مُنَاقَشَةُ سُبُلِ اِسْتِخْدَامِ اللُّغَةِ فِي النُّظُمِ الْقَائِمَةِ وَفِيم يَخُصَّ التَّطْبِيقَاتُ الْحاسُوبِيَّةُ،",
            "AuTNX3zk7qAkvHGxetRWqYanSsQmwsYrChXrXFyPiItoIBsWu1CB+sStla2M4VeANASHxM78i1CfHQQH1YbBy24Tng7emYW44ol6QkFD6D8Zq7QPl+8L1c47lx8RoODEQMvNCbOk5ffUV3/AhONHBXnffrI+0025c+uRGzfqpYki4lBqm9iYU+k3Tvjczq9wU0mkVDEaM34WiQi30MfkJdRbeeYaq6kNvGPunLb3xdjjs5DL720d61Flc5ZfoZm+CBhADy9D9XiVZYLKAlkijALJur9dATYKci6OBOoc2SJS2Clai5hOVzR0yVeyHRgRfH9aLSlWW5dXcUxTo7qqRjNf8W5+J4jF4gNQp5f5d0YA4vPAzjBwSP/5bGzNDslKfcAH",
        );
    }

    #[test]
    fn test_crypt_sec_009() {
        assert_crypt_sec(
            "d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
            "b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
            "75fe686d21a035f0c7cd70da64ba307936e5ca0b20710496a6b6b5f573377bdd",
            "38d1ca0abef9e5f564e89761a86cee04574b6825d3ef2063b10ad75899e4b023",
            "الكل في المجمو عة (5)",
            "AjjRygq++eX1ZOiXYahs7gRXS2gl0+8gY7EK11iZ5LAjbOTrlfrxak5Lki42v2jMPpLSicy8eHjsWkkMtF0i925vOaKG/ZkMHh9ccQBdfTvgEGKzztedqDCAWb5TP1YwU1PsWaiiqG3+WgVvJiO4lUdMHXL7+zKKx8bgDtowzz4QAwI=",
        );
    }

    #[test]
    fn test_crypt_sec_010() {
        assert_crypt_sec(
            "d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
            "b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
            "75fe686d21a035f0c7cd70da64ba307936e5ca0b20710496a6b6b5f573377bdd",
            "4f1a31909f3483a9e69c8549a55bbc9af25fa5bbecf7bd32d9896f83ef2e12e0",
            "𝖑𝖆𝖟𝖞 社會科學院語學研究所",
            "Ak8aMZCfNIOp5pyFSaVbvJryX6W77Pe9MtmJb4PvLhLgh/TsxPLFSANcT67EC1t/qxjru5ZoADjKVEt2ejdx+xGvH49mcdfbc+l+L7gJtkH7GLKpE9pQNQWNHMAmj043PAXJZ++fiJObMRR2mye5VHEANzZWkZXMrXF7YjuG10S1pOU=",
        );
    }

    #[test]
    fn test_crypt_sec_011() {
        assert_crypt_sec(
            "d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
            "b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
            "75fe686d21a035f0c7cd70da64ba307936e5ca0b20710496a6b6b5f573377bdd",
            "a3e219242d85465e70adcd640b564b3feff57d2ef8745d5e7a0663b2dccceb54",
            "🙈 🙉 🙊 0️⃣ 1️⃣ 2️⃣ 3️⃣ 4️⃣ 5️⃣ 6️⃣ 7️⃣ 8️⃣ 9️⃣ 🔟 Powerلُلُصّبُلُلصّبُررً ॣ ॣh ॣ ॣ冗",
            "AqPiGSQthUZecK3NZAtWSz/v9X0u+HRdXnoGY7LczOtUf05aMF89q1FLwJvaFJYICZoMYgRJHFLwPiOHce7fuAc40kX0wXJvipyBJ9HzCOj7CgtnC1/cmPCHR3s5AIORmroBWglm1LiFMohv1FSPEbaBD51VXxJa4JyWpYhreSOEjn1wd0lMKC9b+osV2N2tpbs+rbpQem2tRen3sWflmCqjkG5VOVwRErCuXuPb5+hYwd8BoZbfCrsiAVLd7YT44dRtKNBx6rkabWfddKSLtreHLDysOhQUVOp/XkE7OzSkWl6sky0Hva6qJJ/V726hMlomvcLHjE41iKmW2CpcZfOedg==",
        );
    }

    #[test]
    fn test_crypt_long_001() {
        assert_crypt_long(
            "8fc262099ce0d0bb9b89bac05bb9e04f9bc0090acc181fef6840ccee470371ed",
            "326bcb2c943cd6bb717588c9e5a7e738edf6ed14ec5f5344caa6ef56f0b9cff7",
            "x",
            65535,
            "09ab7495d3e61a76f0deb12cb0306f0696cbb17ffc12131368c7a939f12f56d3",
            "90714492225faba06310bff2f249ebdc2a5e609d65a629f1c87f2d4ffc55330a",
        );
    }

    #[test]
    fn test_crypt_long_002() {
        assert_crypt_long(
            "56adbe3720339363ab9c3b8526ffce9fd77600927488bfc4b59f7a68ffe5eae0",
            "ad68da81833c2a8ff609c3d2c0335fd44fe5954f85bb580c6a8d467aa9fc5dd0",
            "!",
            65535,
            "6af297793b72ae092c422e552c3bb3cbc310da274bd1cf9e31023a7fe4a2d75e",
            "8013e45a109fad3362133132b460a2d5bce235fe71c8b8f4014793fb52a49844",
        );
    }

    #[test]
    fn test_crypt_long_003() {
        assert_crypt_long(
            "7fc540779979e472bb8d12480b443d1e5eb1098eae546ef2390bee499bbf46be",
            "34905e82105c20de9a2f6cd385a0d541e6bcc10601d12481ff3a7575dc622033",
            "🦄",
            16383,
            "a249558d161b77297bc0cb311dde7d77190f6571b25c7e4429cd19044634a61f",
            "b3348422471da1f3c59d79acfe2fe103f3cd24488109e5b18734cdb5953afd15",
        );
    }

    #[test]
    fn test_decrypt_fail_001() {
        assert_decrypt_fail(
            "ca2527a037347b91bea0c8a30fc8d9600ffd81ec00038671e3a0f0cb0fc9f642",
            "#Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbrhdG8VmJdU0MIDf06CUvEvdnr1cp1fiMtlM/GrE92xAc1K5odTpCzUB+mjXgbaqtntBUbTToSUoT0ovrlPwzGjyp",
            DecryptError::UnknownVersion,
        );
    }

    #[test]
    fn test_decrypt_fail_002() {
        assert_decrypt_fail(
            "36f04e558af246352dcf73b692fbd3646a2207bd8abd4b1cd26b234db84d9481",
            "AK1AjUvoYW3IS7C/BGRUoqEC7ayTfDUgnEPNeWTF/reBZFaha6EAIRueE9D1B1RuoiuFScC0Q94yjIuxZD3JStQtE8JMNacWFs9rlYP+ZydtHhRucp+lxfdvFlaGV/sQlqZz",
            DecryptError::UnknownVersion,
        );
    }

    #[test]
    fn test_decrypt_fail_003() {
        assert_decrypt_fail(
            "ca2527a037347b91bea0c8a30fc8d9600ffd81ec00038671e3a0f0cb0fc9f642",
            "Atфupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbrhdG8VmJZE0UICD06CUvEvdnr1cp1fiMtlM/GrE92xAc1EwsVCQEgWEu2gsHUVf4JAa3TpgkmFc3TWsax0v6n/Wq",
            DecryptError::InvalidBase64(base64::DecodeError::InvalidByte(2, 209)),
        );
    }

    #[test]
    fn test_decrypt_fail_004() {
        assert_decrypt_fail(
            "cff7bd6a3e29a450fd27f6c125d5edeb0987c475fd1e8d97591e0d4d8a89763c",
            "Agn/l3ULCEAS4V7LhGFM6IGA17jsDUaFCKhrbXDANholyySBfeh+EN8wNB9gaLlg4j6wdBYh+3oK+mnxWu3NKRbSvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            DecryptError::InvalidHmac,
        );
    }

    #[test]
    fn test_decrypt_fail_005() {
        assert_decrypt_fail(
            "cfcc9cf682dfb00b11357f65bdc45e29156b69db424d20b3596919074f5bf957",
            "AmWxSwuUmqp9UsQX63U7OQ6K1thLI69L7G2b+j4DoIr0oRWQ8avl4OLqWZiTJ10vIgKrNqjoaX+fNhE9RqmR5g0f6BtUg1ijFMz71MO1D4lQLQfW7+UHva8PGYgQ1QpHlKgR",
            DecryptError::InvalidHmac,
        );
    }

    #[test]
    fn test_decrypt_fail_006() {
        assert_decrypt_fail(
            "5254827d29177622d40a7b67cad014fe7137700c3c523903ebbe3e1b74d40214",
            "Anq2XbuLvCuONcr7V0UxTh8FAyWoZNEdBHXvdbNmDZHB573MI7R7rrTYftpqmvUpahmBC2sngmI14/L0HjOZ7lWGJlzdh6luiOnGPc46cGxf08MRC4CIuxx3i2Lm0KqgJ7vA",
            DecryptError::InvalidPadding,
        );
    }

    #[test]
    fn test_decrypt_fail_007() {
        assert_decrypt_fail(
            "fea39aca9aa8340c3a78ae1f0902aa7e726946e4efcd7783379df8096029c496",
            "An1Cg+O1TIhdav7ogfSOYvCj9dep4ctxzKtZSniCw5MwRrrPJFyAQYZh5VpjC2QYzny5LIQ9v9lhqmZR4WBYRNJ0ognHVNMwiFV1SHpvUFT8HHZN/m/QarflbvDHAtO6pY16",
            DecryptError::InvalidPadding,
        );
    }

    #[test]
    fn test_decrypt_fail_008() {
        assert_decrypt_fail(
            "0c4cffb7a6f7e706ec94b2e879f1fc54ff8de38d8db87e11787694d5392d5b3f",
            "Am+f1yZnwnOs0jymZTcRpwhDRHTdnrFcPtsBzpqVdD6b2NZDaNm/TPkZGr75kbB6tCSoq7YRcbPiNfJXNch3Tf+o9+zZTMxwjgX/nm3yDKR2kHQMBhVleCB9uPuljl40AJ8kXRD0gjw+aYRJFUMK9gCETZAjjmrsCM+nGRZ1FfNsHr6Z",
            DecryptError::InvalidPadding,
        );
    }

    #[test]
    fn test_decrypt_fail_009() {
        assert_decrypt_fail(
            "5cd2d13b9e355aeb2452afbd3786870dbeecb9d355b12cb0a3b6e9da5744cd35",
            "",
            DecryptError::InvalidPayloadLength,
        );
    }

    #[test]
    fn test_decrypt_fail_010() {
        assert_decrypt_fail(
            "d61d3f09c7dfe1c0be91af7109b60a7d9d498920c90cbba1e137320fdd938853",
            "Ag==",
            DecryptError::InvalidPayloadLength,
        );
    }

    #[test]
    fn test_decrypt_fail_011() {
        assert_decrypt_fail(
            "873bb0fc665eb950a8e7d5971965539f6ebd645c83c08cd6a85aafbad0f0bc47",
            "AqxgToSh3H7iLYRJjoWAM+vSv/Y1mgNlm6OWWjOYUClrFF8=",
            DecryptError::InvalidPayloadLength,
        );
    }

    #[test]
    fn test_decrypt_fail_012() {
        assert_decrypt_fail(
            "9f2fef8f5401ac33f74641b568a7a30bb19409c76ffdc5eae2db6b39d2617fbe",
            "Ap/2SEZCVFIhYk6qx7nqJxM6TMI1ZoKmAzrO7vBDVJhhuZXWiM20i/tIsbjT0KxkJs2MZjh1oXNYMO9ggfk7i47WQA==",
            DecryptError::InvalidPayloadLength,
        );
    }

    #[test]
    fn test_conversation_key_001() {
        assert_conversation_key_generation_pub(
            "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
            "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
            "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1",
        );
    }

    #[test]
    fn test_conversation_key_002() {
        assert_conversation_key_generation_pub(
            "a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e",
            "03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800",
            "4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b",
        );
    }

    #[test]
    fn test_conversation_key_003() {
        assert_conversation_key_generation_pub(
            "98a5902fd67518a0c900f0fb62158f278f94a21d6f9d33d30cd3091195500311",
            "aae65c15f98e5e677b5050de82e3aba47a6fe49b3dab7863cf35d9478ba9f7d1",
            "9c00b769d5f54d02bf175b7284a1cbd28b6911b06cda6666b2243561ac96bad7",
        );
    }

    #[test]
    fn test_conversation_key_004() {
        assert_conversation_key_generation_pub(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "8b6392dbf2ec6a2b2d5b1477fc2be84d63ef254b667cadd31bd3f444c44ae6ba",
        );
    }

    #[test]
    fn test_message_key_generation_001() {
        assert_message_key_generation(
            "a1a3d60f3470a8612633924e91febf96dc5366ce130f658b1f0fc652c20b3b54",
            "e1e6f880560d6d149ed83dcc7e5861ee62a5ee051f7fde9975fe5d25d2a02d72",
            "f145f3bed47cb70dbeaac07f3a3fe683e822b3715edb7c4fe310829014ce7d76",
            "c4ad129bb01180c0933a160c",
            "027c1db445f05e2eee864a0975b0ddef5b7110583c8c192de3732571ca5838c4",
        );
    }
}
