use assignment_2_solution::{
    StableStorage, ClientRegisterCommand, ClientCommandHeader, ClientRegisterCommandContent, 
    SectorVec, PublicConfiguration, Configuration, run_register_process, RegisterCommand, serialize_register_command, build_stable_storage
};
use ntest::timeout;
use std::path::PathBuf;
use tempfile::tempdir;
use bincode;
use tokio;
use tokio::net::TcpStream;
// use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

// #[tokio::test]
// #[timeout(4000)]
async fn test_recovery() {
    let _ = env_logger::builder().is_test(true).try_init();

    
    let mut storage_dir = tempdir().unwrap().into_path();

    let mut storage = build_stable_storage(storage_dir.clone()).await;

    let cmd = ClientRegisterCommand{
        header: ClientCommandHeader{
            request_identifier: 10,
            sector_idx: 5,
        },
        content: ClientRegisterCommandContent::Write{
            data: SectorVec(vec![33; 4096]),
        },
    };
    let idx : usize = 0;
    // storage.put(&format!("pending{}", idx), &bincode::serialize(&cmd).unwrap()).await.unwrap();

    let tcp_port = 10_000;

    let tcp_locations = vec![("127.0.0.1".to_string(), tcp_port)];

    let hmac_client_key = [2_u8; 32];
    
    let config = Configuration {
        public: PublicConfiguration {
            tcp_locations: tcp_locations.clone(),
            self_rank: 1,
            max_sector: 20,
            storage_dir,
        },
        hmac_system_key: [1; 64],
        hmac_client_key,
    };

    println!("before spawn");
    let handle = tokio::spawn(run_register_process(config));
    println!("after spawn");

    
    
    const EXPECTED_WRITE_RESPONSES_SIZE: usize = 48;
    const EXPECTED_READ_RESPONSES_SIZE: usize  = 48 + 4096;
    
    let mut write_response_buf = [0_u8; EXPECTED_WRITE_RESPONSES_SIZE];
    let mut read_response_buf = [0_u8; EXPECTED_READ_RESPONSES_SIZE];
    
    let compare = |buf : Vec<u8>, data : Vec<u8>| {
        assert_eq!(&data[0..5], &buf[16..21]);
    };
    
    
    let mut read_request_identifier = 222;
    let mut read_cmd = |sector_idx| {
        read_request_identifier += 1;
        log::info!("read_request_identifier: {}", read_request_identifier);
        
        RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: read_request_identifier,
                sector_idx,
            },
            content: ClientRegisterCommandContent::Read{},
        })
    };
    
    let read_cmd_instance = read_cmd(5);
    
    
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let mut stream = tokio::net::TcpStream::connect(tcp_locations[0].clone())
        .await
        .expect("Could not connect to TCP port");
    
    send_cmd(&read_cmd_instance, &mut stream, &hmac_client_key).await;
    
    let buf = &mut read_response_buf;
    
    stream
        .read_exact(buf)
        .await
        .expect("Less data than expected");

    compare(buf.to_vec(), vec![33; 4096]);
}



type HmacSha256 = Hmac<Sha256>;

async fn send_cmd(register_cmd: &RegisterCommand, stream: &mut TcpStream, hmac_client_key: &[u8]) {
    let mut data = Vec::new();
    serialize_register_command(register_cmd, &mut data).unwrap();
    let mut key = HmacSha256::new_varkey(hmac_client_key).unwrap();
    key.update(&data);
    data.extend(key.finalize_reset().into_bytes());

    stream.write_all(&data).await.unwrap();
}

fn hmac_tag_is_ok(key: &[u8], data: &[u8]) -> bool {
    let boundary = data.len() - 32; // - HMAC
    let mut mac = HmacSha256::new_varkey(key).unwrap();
    mac.update(&data[..boundary]);
    mac.verify(&data[boundary..]).is_ok()
}

