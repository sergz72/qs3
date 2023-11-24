use std::io::{Error, ErrorKind};
use std::net::{ToSocketAddrs, UdpSocket};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use pkcs8::DecodePublicKey;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha2::{Sha256, Digest};
use crate::common::common_decrypt;
use crate::network::qsend_to;

pub fn qsend(
    server_public_key: &str,
    host_name: &String,
    data: Vec<u8>,
    read_timeout: u64,
    retries: usize,
) -> Result<Vec<u8>, Error> {
    let addr = host_name
        .to_socket_addrs()?
        .next()
        .ok_or(Error::new(ErrorKind::Unsupported, "invalid address"))?;
    let (encrypted, cipher) = client_encrypt(server_public_key, data)?;
    let socket = UdpSocket::bind((addr.ip(), 0))?;
    let response = qsend_to(socket, addr, encrypted, read_timeout, retries)?;
    common_decrypt(response, &cipher)
}

pub fn client_encrypt(
    server_public_key: &str,
    mut data: Vec<u8>,
) -> Result<(Vec<u8>, Aes256Gcm), Error> {
    let key = RsaPublicKey::from_public_key_pem(server_public_key)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    // random 32 byte AES key
    let mut aes_key = [0u8; 32];
    OsRng.fill_bytes(&mut aes_key);
    let mut rng = rand::thread_rng();
    let rsa_encrypted = key.encrypt(&mut rng, Pkcs1v15Encrypt, &aes_key)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    // adding sha256 hash
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    data.extend_from_slice(hash.as_slice());

    let cipher = Aes256Gcm::new(&aes_key.into());
    let nonce = Aes256Gcm::generate_nonce(rng);

    let aes_encrypted = cipher
        .encrypt(&nonce, data.as_slice())
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;

    let mut result = (rsa_encrypted.len() as u16).to_le_bytes().to_vec();
    result.extend_from_slice(&rsa_encrypted);
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&aes_encrypted);

    Ok((result, cipher))
}
