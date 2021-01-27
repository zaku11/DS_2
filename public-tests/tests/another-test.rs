use assignment_2_solution::{run_register_process, serialize_register_command, ClientCommandHeader, ClientRegisterCommand, ClientRegisterCommandContent, Configuration, PublicConfiguration, RegisterCommand, SectorVec, MAGIC_NUMBER, deserialize_register_command};
use hmac::{Hmac, Mac, NewMac};
use ntest::timeout;
use sha2::Sha256;
use std::convert::TryInto;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::ops::Deref;

static HMAC_TAG_SIZE: usize = 32;


#[tokio::test]
#[timeout(2000)]
async fn one_reads_other_writes() {
    // given
    let hmac_client_key = [5; 32];
    let tcp_port = 30_281;
    let tcp_port2 = 30_282;
    let storage_dir = tempdir().unwrap();
    let storage_dir2 = tempdir().unwrap();
    let request_identifier = 1778;

    let config = Configuration {
        public: PublicConfiguration {
            tcp_locations: vec![("127.0.0.1".to_string(), tcp_port), ("127.0.0.1".to_string(), tcp_port2)],
            self_rank: 1,
            max_sector: 20,
            storage_dir: storage_dir.into_path(),
        },
        hmac_system_key: [1; 64],
        hmac_client_key,
    };
    let config2 = Configuration{
        public: PublicConfiguration {
            tcp_locations: vec![("127.0.0.1".to_string(), tcp_port), ("127.0.0.1".to_string(), tcp_port2)],
            self_rank: 2,
            max_sector: 20,
            storage_dir: storage_dir2.into_path(),
        },
        hmac_system_key: [1; 64],
        hmac_client_key,
    };

    tokio::spawn(run_register_process(config));
    tokio::spawn(run_register_process(config2));
  //  tokio::spawn(run_register_process(config2));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut stream = TcpStream::connect(("127.0.0.1", tcp_port))
        .await
        .expect("Could not connect to TCP port");
     let mut stream2 = TcpStream::connect(("127.0.0.1", tcp_port2))
         .await.expect("couldnt connect to tcp port");
    let write_cmd = RegisterCommand::Client(ClientRegisterCommand {
        header: ClientCommandHeader {
            request_identifier,
            sector_idx: 12,
        },
        content: ClientRegisterCommandContent::Write {
            data: SectorVec(vec![3; 4096]),
        },
    });

    // when
    send_cmd(&write_cmd, &mut stream, &hmac_client_key.clone()).await;
    let read_cmd = RegisterCommand::Client(ClientRegisterCommand{ header: ClientCommandHeader{
        request_identifier: request_identifier+1, sector_idx: 12 }, content: ClientRegisterCommandContent::Read });
    // then
    const EXPECTED_RESPONSES_SIZE: usize = 48;
    let mut buf = [0_u8; EXPECTED_RESPONSES_SIZE];

    stream
        .read_exact(&mut buf)
        .await
        .expect("Less data then expected");
    send_cmd(&read_cmd, &mut stream2, &hmac_client_key.clone()).await;


    let mut buf2 : Vec<u8> = vec![0; 4096+EXPECTED_RESPONSES_SIZE];
    stream2.read_exact( buf2.as_mut_slice())
        .await
        .expect("less data than expected");
    //asserts for write response
    assert_eq!(&buf[0..4], MAGIC_NUMBER.as_ref());
    assert_eq!(buf[7], 0x42);
    assert_eq!(
        u64::from_be_bytes(buf[8..16].try_into().unwrap()),
        request_identifier
    );
    assert!(hmac_tag_is_ok(&hmac_client_key, &buf));
    assert_eq!(&buf2[0..4], MAGIC_NUMBER.as_ref());
    assert_eq!(buf2[7], 0x41);
    assert_eq!(
    u64::from_be_bytes(buf2[8..16].try_into().unwrap()),
    (request_identifier+1)
    );
    assert_eq!(&buf2[16..4112], vec![3_u8; 4096].as_slice());
    assert!(hmac_tag_is_ok(&hmac_client_key, &buf2));
}


#[tokio::test]
#[timeout(250000)]
async fn multiple_reads_and_writes(){
    const EXPECTED_RESPONSES_SIZE: usize = 48;
    let hmac_client_key = [5; 32];
    let tcp_port = 31_283;
    let tcp_port2 = 31_289;
    let storage_dir = tempdir().unwrap();
    let storage_dir2 = tempdir().unwrap();
    let request_identifier = 1778;

    let config = Configuration {
        public: PublicConfiguration {
            tcp_locations: vec![("127.0.0.1".to_string(), tcp_port), ("127.0.0.1".to_string(), tcp_port2)],
            self_rank: 1,
            max_sector: 256,
            storage_dir: storage_dir.into_path(),
        },
        hmac_system_key: [1; 64],
        hmac_client_key,
    };
    let config2 = Configuration{
        public: PublicConfiguration {
            tcp_locations: vec![("127.0.0.1".to_string(), tcp_port), ("127.0.0.1".to_string(), tcp_port2)],
            self_rank: 2,
            max_sector: 256,
            storage_dir: storage_dir2.into_path(),
        },
        hmac_system_key: [1; 64],
        hmac_client_key,
    };

    tokio::spawn(run_register_process(config));
    tokio::spawn(run_register_process(config2));
    //  tokio::spawn(run_register_process(config2));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut stream = TcpStream::connect(("127.0.0.1", tcp_port))
        .await
        .expect("Could not connect to TCP port");
    let mut stream2 = TcpStream::connect(("127.0.0.1", tcp_port2))
        .await.expect("couldnt connect to tcp port");

    for i in 0..10 {
        let mut write_cmd = RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: request_identifier + i as u64,
                sector_idx: 253 as u64,

            },
            content: ClientRegisterCommandContent::Write {
                data: SectorVec(vec![i as u8; 4096]),
            },
        });
        send_cmd(&write_cmd, &mut stream, &hmac_client_key.clone()).await;
    }
    for i in 0..10 {
        let mut buf = [0_u8; EXPECTED_RESPONSES_SIZE];
        stream
            .read_exact(&mut buf)
            .await
            .expect("Less data then expected");
        //writes should happen in correct order , since they concern single sector
        assert_eq!(&buf[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf[7], 0x42);
        assert_eq!(
            u64::from_be_bytes(buf[8..16].try_into().unwrap()),
            request_identifier + i
        );
        assert!(hmac_tag_is_ok(&hmac_client_key, &buf));
    }
    // when
    for i in 0..10 {
        let mut read_cmd = RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: request_identifier + 100 + i,
                sector_idx: 253 as u64,
            },
            content: ClientRegisterCommandContent::Read
        });
        // then
        send_cmd(&read_cmd, &mut stream2, &hmac_client_key.clone()).await;
    }
    for i in 0..10 {
        let mut buf2: Vec<u8> = vec![0; 4096 + EXPECTED_RESPONSES_SIZE];
        stream2.read_exact(buf2.as_mut_slice())
            .await
            .expect("less data than expected");
        assert_eq!(&buf2[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf2[7], 0x41);
        assert_eq!(
            u64::from_be_bytes(buf2[8..16].try_into().unwrap()),
            (request_identifier+100 +i)
        );
        assert_eq!(&buf2[16..4112], vec![9_u8; 4096].as_slice());
        assert!(hmac_tag_is_ok(&hmac_client_key, &buf2));
    }

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
    let boundary = data.len() - HMAC_TAG_SIZE;
    let mut mac = HmacSha256::new_varkey(key).unwrap();
    mac.update(&data[..boundary]);
    mac.verify(&data[boundary..]).is_ok()
}
