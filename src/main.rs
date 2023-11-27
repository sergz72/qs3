use std::env::args;
use std::fs;
use std::io::{Error, ErrorKind};
use std::num::ParseIntError;
use qs3_lib::client::qsend;
use qs3_lib::load_key_file;
use qs3_lib::network::qserver;

fn usage() -> Result<(), Error> {
    println!("Usage: qs3 server port|client host:port file_name");
    Ok(())
}

fn main() -> Result<(), Error> {
    let arguments: Vec<String> = args().skip(1).collect();
    let l = arguments.len();
    if l < 1 || l > 3 {
        return usage();
    }

    match arguments[0].as_str() {
        "client" => {
            if l != 3 {
                usage()
            } else { send_file_to_server(arguments) }
        }
        "server" => {
            if l != 2 {
                usage()
            } else { start_server(arguments[1].clone()) }
        }
        _ => usage()
    }
}

fn start_server(port: String) -> Result<(), Error> {
    let port: u16 = port.parse()
        .map_err(|e:  ParseIntError|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    qserver(load_key_file("test_data/test_rsa.pem")?.as_str(), port,
            |in_data| {
                Ok(Some(in_data.to_vec()))
            })
}

fn send_file_to_server(arguments: Vec<String>) -> Result<(), Error> {
    let data = fs::read(&arguments[2])?;
    let response = qsend(load_key_file("test_data/test_rsa.pem.pub")?.as_str(),
          &arguments[1], data.clone(), 2, 3)?;
    if data != response {
        println!("wrong data received");
    }
    Ok(())
}
