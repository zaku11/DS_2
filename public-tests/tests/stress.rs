use assignment_2_solution::{
    RegisterClient, Send, Broadcast, SystemRegisterCommand, Configuration, PublicConfiguration, run_register_process, 
    RegisterCommand, ClientRegisterCommand, ClientRegisterCommandContent, serialize_register_command, SectorVec, ClientCommandHeader,
};
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use ntest::timeout;
use lazy_static::lazy_static;
use tempfile::tempdir;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use tokio::task::JoinHandle;
use std::convert::TryInto;


#[tokio::test]
#[timeout(200000)]
async fn stress_test() {
    let _ = env_logger::builder().is_test(true).try_init();

    // let range = 1..3;
    let range = 1..10;

    let mut addrs = Vec::<(String, u16)>::new();
    let mut tcp_port = 10_000;
    let hmac_client_key = [0x61; 32]; // =0x61 == 'a'

    for _ in range.clone() {
        addrs.push(("127.0.0.1".to_string(), tcp_port));
        tcp_port += 1;
    }

    let mut handles = vec![];

    for i in range {
        assert!(i > 0);
        let config = Configuration {
            public: PublicConfiguration {
                tcp_locations: addrs.clone(),
                self_rank: i,
                max_sector: 20,
                storage_dir: tempdir().unwrap().into_path(),
            },
            hmac_system_key: [1; 64],
            hmac_client_key,
        };
        handles.push(tokio::spawn(run_register_process(config)));
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut request_identifier = 1778;
    let mut read_request_identifier = 1778000;

    let mut write_cmd = |sector_idx, byte : u8| {
        request_identifier += 1;
        log::info!("request_identifier: {}", request_identifier);

        RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier,
                sector_idx,
            },
            content: ClientRegisterCommandContent::Write {
                data: SectorVec(vec![byte; 4096]),
            },
        })
    };

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

    let mut stream = TcpStream::connect(addrs[0].clone())
        .await
        .expect("Could not connect to TCP port");

    // when
    // let cmd = write_cmd(0, 0_u8);
    // send_cmd(&cmd, &mut stream, &hmac_client_key).await;

    const EXPECTED_WRITE_RESPONSES_SIZE: usize = 48;
    const EXPECTED_READ_RESPONSES_SIZE: usize  = 48 + 4096;

    let mut write_response_buf = [0_u8; EXPECTED_WRITE_RESPONSES_SIZE];
    let mut read_response_buf = [0_u8; EXPECTED_READ_RESPONSES_SIZE];

    let compare = |buf : Vec<u8>, data : Vec<u8>| {
        assert_eq!(&data[0..5], &buf[16..21]);
    };

    let buf = &mut write_response_buf;


    let SECONDS = 2;
    let RANGE : u8 = 25 * SECONDS;

    let t1 = Instant::now();
    
    for i in 1..RANGE {
        let cmd = write_cmd(0, i);
        send_cmd(&cmd, &mut stream, &hmac_client_key).await;
        
        let buf = &mut write_response_buf;
        
        stream
            .read_exact(buf)
            .await
            .expect("Less data than expected");
    }
    
    println!("CZAS: {}", t1.elapsed().as_millis());        

    drop(stream);
    
    tokio::time::sleep(Duration::from_millis(1000 as u64 * SECONDS as u64)).await;

    let buf = &mut read_response_buf;

    let mut stream = TcpStream::connect(addrs[0].clone())
    .await
    .expect("Could not connect to TCP port");

    let cmd = read_cmd(0);
    send_cmd(&cmd, &mut stream, &hmac_client_key).await;

    stream
        .read_exact(buf)
        .await
        .expect("Less data than expected");

    compare(buf.to_vec(), vec![RANGE - 1; 4096]);
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

