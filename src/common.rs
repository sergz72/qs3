/*

Client message structure:
|RSA part length - 2 bytes|AES key encrypted with RSA|AES gcm nonce - 12 bytes|Request encrypted with AES-GCM|

Server message structure:
|AES gcm nonce - 12 bytes|Response encrypted with AES-GCM|

Network packet structure (hmac key = sha256 of RSA public key file):
|packet number - 2 byte|total number of packets - 2 byte|data - maximum 1418 bytes|hmac sha256 of packet data - 32 byte|

Retry packet structure:
|packet number - 2 byte|hmac sha256 of packet data - 32 byte|

*/

use std::fs;
use std::io::{Error, ErrorKind};
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

pub const MAX_DATA_LENGTH: usize = 1418;
pub const MAX_PACKET_SIZE: usize = 1454;
pub const BUFFER_SIZE: usize = MAX_PACKET_SIZE + 1;

/*fn check_hash(decoded: Vec<u8>) -> Result<Vec<u8>, Error> {
    if decoded.len() < 32 {
        return Err(Error::new(ErrorKind::InvalidData, "check_hash: too short data"));
    }
    let mut hasher = Sha256::new();
    let l = decoded.len() - 32;
    let d = &decoded[0..l];
    hasher.update(d);
    let hash = hasher.finalize();
    let hash_bytes = hash.as_slice();
    if *hash_bytes != decoded[l..] {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "data hash does not match",
        ));
    }
    Ok(d.to_vec())
}*/

pub fn common_decrypt(response: Vec<u8>, cipher: &Aes256Gcm) -> Result<Vec<u8>, Error> {
    let nonce = aes_gcm::Nonce::from_slice(&response[0..12]);
    cipher.decrypt(nonce, &response[12..])
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
}

pub fn build_private_key(private_key: &str) -> Result<RsaPrivateKey, Error> {
    RsaPrivateKey::from_pkcs8_pem(private_key)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
}

pub fn load_key_file(file_name: &str) -> Result<String, Error> {
    fs::read_to_string(file_name)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use rand::Rng;
    use rand::rngs::ThreadRng;
    use rsa::RsaPrivateKey;
    use crate::client::client_encrypt;
    use crate::common::{build_private_key, common_decrypt, load_key_file};
    use crate::server::packet_handler;

    #[test]
    fn test_encryption() -> Result<(), Error> {
        let (public_key, private_key) = load_test_keys()?;
        let mut rng = rand::thread_rng();
        let pk = public_key.as_str();

        let src_data: Vec<u8> = (0..100).map(|_| rng.gen()).collect();
        test_encryption_data(pk, &private_key, src_data, &mut rng)?;

        let src_data: Vec<u8> = (0..20000).map(|_| rng.gen()).collect();
        test_encryption_data(pk, &private_key, src_data, &mut rng)?;

        let src_data: Vec<u8> = (0..200000).map(|_| rng.gen()).collect();
        test_encryption_data(pk, &private_key, src_data, &mut rng)
    }

    fn test_encryption_data(public_key: &str, private_key: &RsaPrivateKey, src_data: Vec<u8>,
                            rng: &mut ThreadRng) -> Result<(), Error> {
        let (encrypted, cipher) = client_encrypt(public_key, src_data.clone())?;
        let response = packet_handler(&private_key, encrypted.as_slice(),
                                      |in_data| {
                                          Ok(Some(in_data))
                                      }, rng)?;
        assert!(response.is_some());
        let decrypted = common_decrypt(response.unwrap(), &cipher)?;
        assert_eq!(decrypted, src_data);
        Ok(())
    }

    fn load_test_keys() -> Result<(String, RsaPrivateKey), Error> {
        let public_key = load_key_file("test_data/test_rsa.pem.pub")?;
        let private_key = build_private_key(load_key_file("test_data/test_rsa.pem")?.as_str())?;
        Ok((public_key, private_key))
    }
}