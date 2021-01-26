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
use std::collections::{HashMap, HashSet};

static HMAC_TAG_SIZE: usize = 32;


// #[tokio::test]
// #[timeout(45000)]
// async fn read_write_different_sectors(){
//     const EXPECTED_RESPONSES_SIZE: usize = 48;
//     let hmac_client_key = [5; 32];
//     let tcp_port = 31_283;
//     let tcp_port2 = 31_289;
//     let storage_dir = tempdir().unwrap();
//     let storage_dir2 = tempdir().unwrap();
//     let request_identifier = 1778;

//     let config = Configuration {
//         public: PublicConfiguration {
//             tcp_locations: vec![("127.0.0.1".to_string(), tcp_port), ("127.0.0.1".to_string(), tcp_port2)],
//             self_rank: 1,
//             max_sector: 256,
//             storage_dir: storage_dir.into_path(),
//         },
//         hmac_system_key: [1; 64],
//         hmac_client_key,
//     };
//     let config2 = Configuration{
//         public: PublicConfiguration {
//             tcp_locations: vec![("127.0.0.1".to_string(), tcp_port), ("127.0.0.1".to_string(), tcp_port2)],
//             self_rank: 2,
//             max_sector: 256,
//             storage_dir: storage_dir2.into_path(),
//         },
//         hmac_system_key: [1; 64],
//         hmac_client_key,
//     };

//     tokio::spawn(run_register_process(config));
//     tokio::spawn(run_register_process(config2));
//     //  tokio::spawn(run_register_process(config2));
//     tokio::time::sleep(Duration::from_millis(300)).await;
//     let mut stream = TcpStream::connect(("127.0.0.1", tcp_port))
//         .await
//         .expect("Could not connect to TCP port");
//     let mut stream2 = TcpStream::connect(("127.0.0.1", tcp_port2))
//         .await.expect("couldnt connect to tcp port");

//     for i in 0..10{
//         let mut write_cmd = RegisterCommand::Client(ClientRegisterCommand {
//             header: ClientCommandHeader {
//                 request_identifier: request_identifier + i as u64,
//                 sector_idx: i as u64,

//             },
//             content: ClientRegisterCommandContent::Write {
//                 data: SectorVec(vec![i; 4096]),
//             },
//         });
//         send_cmd(&write_cmd, &mut stream, &hmac_client_key.clone()).await;
//     }

//     for i in 0..10{
//         let mut buf = [0_u8; EXPECTED_RESPONSES_SIZE];
//         stream
//             .read_exact(&mut buf)
//             .await
//             .expect("Less data then expected");
//         //writes should happen in correct order , since they concern single sector
//         println!("received buffer: {:?}", buf);
//         assert_eq!(&buf[0..4], MAGIC_NUMBER.as_ref());
//         assert_eq!(buf[7], 0x42);
//         assert_eq!(
//             u64::from_be_bytes(buf[8..16].try_into().unwrap()),
//             request_identifier + i
//         );
//         assert!(hmac_tag_is_ok(&hmac_client_key, &buf));
//         println!("ITERATION {:?} IS CORRENT! WELL DONE", i);
//     }
//     // when
//     for i in 0..10 {
//         let mut read_cmd = RegisterCommand::Client(ClientRegisterCommand {
//             header: ClientCommandHeader {
//                 request_identifier: request_identifier + 100 + i,
//                 sector_idx: i as u64,
//             },
//             content: ClientRegisterCommandContent::Read
//         });
//         // then
//         send_cmd(&read_cmd, &mut stream2, &hmac_client_key.clone()).await;
//     }
//     for i in 0..10 {
//         let mut buf2: Vec<u8> = vec![0; 4096 + EXPECTED_RESPONSES_SIZE];
//         stream2.read_exact(buf2.as_mut_slice())
//             .await
//             .expect("less data than expected");
//         assert_eq!(&buf2[0..4], MAGIC_NUMBER.as_ref());
//         assert_eq!(buf2[7], 0x41);
//         assert_eq!(
//             u64::from_be_bytes(buf2[8..16].try_into().unwrap()),
//             (request_identifier+100 +i)
//         );
//         assert_eq!(&buf2[16..4112], vec![i as u8; 4096].as_slice());
//         assert!(hmac_tag_is_ok(&hmac_client_key, &buf2));
//     }
//     println!("NICE, WRITES TO MULTIPLE SECTORS SEEM TO BE WORKING.");
// }

#[tokio::test]
#[timeout(45000)]
async fn writes_should_overwrite(){
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

    let N = 10 as u64;

    for i in 0..N{
        let mut write_cmd = RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: request_identifier + i as u64,
                sector_idx: i as u64,

            },
            content: ClientRegisterCommandContent::Write {
                data: SectorVec(vec![i as u8; 4096]),
            },
        });
        send_cmd(&write_cmd, &mut stream, &hmac_client_key.clone()).await;
    }

    for i in 0..N{
        let mut write_cmd = RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: request_identifier + N + i as u64,
                sector_idx: i as u64,

            },
            content: ClientRegisterCommandContent::Write {
                data: SectorVec(vec![N as u8 + i as u8; 4096]),
            },
        });
        send_cmd(&write_cmd, &mut stream, &hmac_client_key.clone()).await;
    }

    let mut all_ids = HashSet::new();
    for i in 0..(2 * N){
        let mut buf = [0_u8; EXPECTED_RESPONSES_SIZE];
        stream
            .read_exact(&mut buf)
            .await
            .expect("Less data then expected");

        println!("received buffer: {:?}", buf);
        assert_eq!(&buf[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf[7], 0x42);
        // assert_eq!(
        //     u64::from_be_bytes(buf[8..16].try_into().unwrap()),
        //     request_identifier + i
        // );
        all_ids.insert(u64::from_be_bytes(buf[8..16].try_into().unwrap()));

        assert!(hmac_tag_is_ok(&hmac_client_key, &buf));
        println!("ITERATION {:?} IS CORRENT! WELL DONE", i);
    }
    for i in 0..(2 * N) {
        assert!(all_ids.contains(&(request_identifier + i)));
    }

    // when
    for i in 0..N {
        let mut read_cmd = RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: request_identifier + N + N + i,
                sector_idx: i as u64,
            },
            content: ClientRegisterCommandContent::Read
        });
        // then
        send_cmd(&read_cmd, &mut stream2, &hmac_client_key.clone()).await;
    }
    
    let mut all_answers : HashMap<u64, Vec<u8> > = HashMap::new();
    for i in 0..N {
        let mut buf2: Vec<u8> = vec![0; 4096 + EXPECTED_RESPONSES_SIZE];
        stream2.read_exact(buf2.as_mut_slice())
            .await
            .expect("less data than expected");
        assert_eq!(&buf2[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf2[7], 0x41);
        // assert_eq!(
        //     u64::from_be_bytes(buf2[8..16].try_into().unwrap()),
        //     (request_identifier + 100 + i)
        // );
        all_answers.insert(u64::from_be_bytes(buf2[8..16].try_into().unwrap()), buf2[16..4112].to_vec());
        // assert_eq!(&buf2[16..4112], vec![i as u8; 4096].as_slice());
        assert!(hmac_tag_is_ok(&hmac_client_key, &buf2));
    }
    for i in 0..N {
        let id = request_identifier + N + N + i;
        for (key, _) in &all_answers {
            println!("{:?}", key);
        }
        assert!(all_answers.contains_key(&id));
        assert_eq!(all_answers.get(&id).unwrap(), &vec![(N + i) as u8; 4096].as_slice());
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
