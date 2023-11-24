use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::thread::sleep;
use std::time::Duration;
use crate::common::{BUFFER_SIZE, build_private_key};
use crate::server::packet_handler;

pub fn qsend_to(
    socket: UdpSocket,
    addr: SocketAddr,
    data: Vec<u8>,
    read_timeout: u64,
    retries: usize,
) -> Result<Vec<u8>, Error> {
    let mut err = None;
    let mut buffer = [0u8; BUFFER_SIZE];
    socket.set_read_timeout(Some(Duration::new(read_timeout, 0)))?;
    for _i in 0..retries {
        send_data(&socket, &data, addr)?;
        //todo: state machine & retry logic
        match socket.recv_from(&mut buffer) {
            Ok((amt, _src)) => return Ok(buffer[0..amt].to_vec()),
            Err(e) => err = Some(e),
        }
    }
    Err(err.unwrap())
}

fn send_data(socket: &UdpSocket, data: &Vec<u8>, addr: SocketAddr) -> Result<(), Error> {
    for packet in prepare_packets(data) {
        socket.send_to(packet.as_slice(), addr)?;
    }
    Ok(())
}

fn prepare_packets(data: &Vec<u8>) -> Vec<Vec<u8>> {
    todo!()
}

pub fn qserver(
    private_key: &str,
    port: u16,
    handler: fn(data: Vec<u8>) -> Result<Option<Vec<u8>>, Error>,
) -> Result<(), Error> {
    let key = build_private_key(private_key)?;
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)))?;
    socket.set_nonblocking(true)?;
    println!("UDP server started on port {}", port);
    let mut buf = [0; BUFFER_SIZE];
    let mut rng = rand::thread_rng();
    let ms20 = Duration::from_millis(20);
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                println!("Incoming packet with size {} from {}", n, src);
                let data_to_send = packet_handler(&key, &buf[0..n], handler, &mut rng)?;
                if let Some(data) = data_to_send {
                    if let Err(e) = send_data(&socket, &data, src) {
                        println!("send error {}", e.to_string());
                    } else {
                        println!("response sent.");
                    }
                }
            }
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    sleep(ms20);
                } else {
                    return Err(e);
                }
            }
        }
    }
}
