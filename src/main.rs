use std::env::args;
use std::fs;
use std::io::{Error, ErrorKind};
use std::num::ParseIntError;
use qs3_lib::client::qsend;
use qs3_lib::load_key_file;
use qs3_lib::network::{QHandler, qserver};
use s3cli_lib::{build_key_info, KeyInfo, S3KeyInfo};

/*

S3 key file format
line1: provider id (aws, gcp, custom url, custom noprefix url)
line2: region
line3: s3 key
line4: s3 secret hash (sha256)

Server config file format:
line1: host:port
line2: s3 secret

*/

struct ServerConfig {
    host: String,
    s3_secret: String
}

impl ServerConfig {
    fn new(data: Vec<u8>) -> Result<ServerConfig, Error> {
        let text =
            String::from_utf8(data).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
        let lines: Vec<String> = text
            .split('\n')
            .map(|v| v.to_string().trim().to_string())
            .collect();
        if lines.len() < 2 {
            return Err(Error::new(ErrorKind::InvalidData, "invalid server configuration file"));
        }
        Ok(ServerConfig{ host: lines[0].trim().to_string(), s3_secret: lines[1].trim().to_string()})
    }

    fn build_request(&self, method: u8, file_name: &String) -> Vec<u8> {
        let mut request = Vec::new();
        request.push(method);
        request.push(file_name.len() as u8);
        request.extend_from_slice(file_name.as_bytes());
        request.extend_from_slice(self.s3_secret.as_bytes());
        request
    }
}

struct RequestInfo {
    method: String,
    file_name: String,
    s3_secret: String
}

struct ServerHandler {
    key_info: S3KeyInfo
}

impl QHandler for ServerHandler {
    fn handle(&self, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let decoded = decode_data(data)?;
        let new_key_info = S3KeyInfo::new_from_key_info(&self.key_info, decoded.s3_secret)?;
        let now = chrono::Utc::now();
        let url = new_key_info.build_presigned_url(decoded.method.as_str(), now, &decoded.file_name, 60)?;
        Ok(Some(url.as_bytes().to_vec()))
    }
}

fn usage() -> Result<(), Error> {
    println!("Usage: qs3 rsa_key_file [server port s3_key_file|client server_config_file [get|put] remote_file]");
    Ok(())
}

fn main() -> Result<(), Error> {
    let arguments: Vec<String> = args().skip(1).collect();
    let l = arguments.len();
    if l != 4 && l != 5 {
        return usage();
    }

    let rsa_key = load_key_file(arguments[0].as_str())?;

    match arguments[1].as_str() {
        "client" => {
            if l != 5 {
                usage()
            } else { send_request_to_server(rsa_key, arguments) }
        }
        "server" => {
            if l != 4 {
                usage()
            } else { start_server(rsa_key, &arguments[2], &arguments[3]) }
        }
        _ => usage()
    }
}

fn start_server(rsa_key: String, port: &String, s3_key_file_name: &String) -> Result<(), Error> {
    let port: u16 = port.parse()
        .map_err(|e:  ParseIntError|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    let data = fs::read(s3_key_file_name)?;
    let key_info = build_key_info(data)?;
    let handler = Box::new(ServerHandler{ key_info });
    qserver(rsa_key.as_str(), port, handler)
}

fn decode_data(data: &[u8]) -> Result<RequestInfo, Error> {
    let l = data.len();
    if l < 4 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid data length"));
    }
    let method = match data[0] {
        0 => "GET".to_string(),
        1 => "PUT".to_string(),
        _ => return Err(Error::new(ErrorKind::InvalidData, "invalid operation id"))
    };
    let file_name_length = data[1] as usize;
    if file_name_length == 0 || l < file_name_length + 3 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid file name length"));
    }
    let end = 2 + file_name_length;
    let file_name = String::from_utf8(data[2..end].to_vec())
        .map_err(|_e|Error::new(ErrorKind::InvalidData, "invalid name"))?;
    let s3_secret = String::from_utf8(data[end..l].to_vec())
        .map_err(|_e|Error::new(ErrorKind::InvalidData, "invalid secret"))?;

    Ok(RequestInfo{
        method,
        file_name,
        s3_secret,
    })
}

fn send_request_to_server(rsa_key: String, arguments: Vec<String>) -> Result<(), Error> {
    let method = match arguments[3].as_str() {
        "get" => 0u8,
        "put" => 1u8,
        _ => return Err(Error::new(ErrorKind::InvalidInput, "invalid operation, only get or put are allowed"))
    };
    let server_config = ServerConfig::new(fs::read(&arguments[2])?)?;
    let data = server_config.build_request(method, &arguments[4]);
    let response = qsend(rsa_key.as_str(), &server_config.host, data, 2, 3)?;
    let url = String::from_utf8(response)
        .map_err(|_e|Error::new(ErrorKind::InvalidData, "incorrect response from server"))?;
    println!("{}", url);
    Ok(())
}
