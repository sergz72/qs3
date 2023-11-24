use std::io::{Error, ErrorKind};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use rand::rngs::ThreadRng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use crate::common::common_decrypt;

fn server_encrypt(data: Vec<u8>, cipher: Aes256Gcm, rng: &mut ThreadRng) -> Result<Vec<u8>, Error> {
    let nonce = Aes256Gcm::generate_nonce(rng);
    let encoded = cipher.encrypt(&nonce, data.as_slice())
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    let mut result = nonce.to_vec();
    result.extend_from_slice(&encoded);
    Ok(result)
}

pub fn packet_handler(
    key: &RsaPrivateKey,
    data: &[u8],
    handler: fn(data: Vec<u8>) -> Result<Option<Vec<u8>>, Error>,
    rng: &mut ThreadRng,
) -> Result<Option<Vec<u8>>, Error> {
    if data.len() <= 2 {
        println!("too short request");
        return Ok(None);
    }

    let mut length_data = [0u8; 2];
    length_data.copy_from_slice(&data[0..2]);
    let rsa_part_length = u16::from_le_bytes(length_data) as usize;

    if data.len() <= 2 + rsa_part_length + 12 + 32 {
        println!("RSA part length is incorrect");
        return Ok(None);
    }

    match key.decrypt(Pkcs1v15Encrypt, &data[2..2+rsa_part_length]) {
        Ok(key_data) => {
            if key_data.len() != 32 {
                return Err(Error::new(ErrorKind::InvalidData, "RSA decrypted data has invalid length"));
            }
            let mut aes_key = [0u8; 32];
            aes_key.copy_from_slice(key_data.as_slice());
            let cipher = Aes256Gcm::new(&aes_key.into());
            let decrypted = common_decrypt(data[2+rsa_part_length..].to_vec(), &cipher)?;
            run_handler(decrypted, cipher, handler, rng)
        },
        Err(e) => {
            println!("RSA decrypt error {}", e.to_string());
            Ok(None)
        }
    }
}

fn run_handler(
    data: Vec<u8>,
    cipher: Aes256Gcm,
    handler: fn(data: Vec<u8>) -> Result<Option<Vec<u8>>, Error>,
    rng: &mut ThreadRng,
) -> Result<Option<Vec<u8>>, Error> {
    match handler(data) {
        Ok(r) => {
            if let Some(response) = r {
                match server_encrypt(response, cipher, rng) {
                    Ok(encoded) => Ok(Some(encoded)),
                    Err(_e) => {
                        println!("response encrypt error");
                        Ok(None)
                    }
                }
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            println!("handler returned error {}", e);
            Err(e)
        }
    }
}
