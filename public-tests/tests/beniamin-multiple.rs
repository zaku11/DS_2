use assignment_2_solution::{run_register_process, serialize_register_command, ClientCommandHeader, ClientRegisterCommand, ClientRegisterCommandContent, Configuration, PublicConfiguration, RegisterCommand, SectorVec, MAGIC_NUMBER};
use hmac::{Hmac, Mac, NewMac};
use ntest::timeout;
use sha2::Sha256;
use std::convert::TryInto;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::collections::{HashMap, HashSet};

static HMAC_TAG_SIZE: usize = 32;


const N : u64 = 10;

#[tokio::test]
#[timeout(45000)]
async fn read_write_different_sectors(){
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
            max_sector: 1024,
            storage_dir: storage_dir.into_path(),
        },
        hmac_system_key: [1; 64],
        hmac_client_key,
    };
    let config2 = Configuration{
        public: PublicConfiguration {
            tcp_locations: vec![("127.0.0.1".to_string(), tcp_port), ("127.0.0.1".to_string(), tcp_port2)],
            self_rank: 2,
            max_sector: 1024,
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

    for i in 0..N{
        let write_cmd = RegisterCommand::Client(ClientRegisterCommand {
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

    for i in 0..N {
        let mut buf = [0_u8; EXPECTED_RESPONSES_SIZE];
        stream
            .read_exact(&mut buf)
            .await
            .expect("Less data then expected");
        //writes should happen in correct order , since they concern single sector
        println!("received buffer: {:?}", buf);
        assert_eq!(&buf[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf[7], 0x42);
        assert_eq!(
            u64::from_be_bytes(buf[8..16].try_into().unwrap()),
            request_identifier + i
        );
        assert!(hmac_tag_is_ok(&hmac_client_key, &buf));
        println!("ITERATION {:?} IS CORRENT! WELL DONE", i);
    }
    // when
    for i in 0..N {
        let read_cmd = RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: request_identifier + N + i,
                sector_idx: i as u64,
            },
            content: ClientRegisterCommandContent::Read
        });
        // then
        send_cmd(&read_cmd, &mut stream2, &hmac_client_key.clone()).await;
    }

    let mut all_answers : HashMap<u64, Vec<u8> > = HashMap::new();
    for _ in 0..N {
        let mut buf2: Vec<u8> = vec![0; 4096 + EXPECTED_RESPONSES_SIZE];
        stream2.read_exact(buf2.as_mut_slice())
            .await
            .expect("less data than expected");
        assert_eq!(&buf2[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf2[7], 0x41);
        all_answers.insert(u64::from_be_bytes(buf2[8..16].try_into().unwrap()), buf2[16..4112].to_vec());
        assert!(hmac_tag_is_ok(&hmac_client_key, &buf2));
    }

    for i in 0..N {
        let id = request_identifier + N + i;
        assert!(all_answers.contains_key(&id));
        assert_eq!(all_answers.get(&id).unwrap(), &vec![i as u8; 4096].as_slice());
    }

    println!("NICE, WRITES TO MULTIPLE SECTORS SEEM TO BE WORKING.");
}

#[tokio::test]
#[timeout(45000)]
async fn writes_should_overwrite(){
    const EXPECTED_RESPONSES_SIZE: usize = 48;
    let hmac_client_key = [5; 32];
    let tcp_port = 31_284;
    let tcp_port2 = 31_290;
    let storage_dir = tempdir().unwrap();
    let storage_dir2 = tempdir().unwrap();
    let request_identifier = 1778;

    let config = Configuration {
        public: PublicConfiguration {
            tcp_locations: vec![("127.0.0.1".to_string(), tcp_port), ("127.0.0.1".to_string(), tcp_port2)],
            self_rank: 1,
            max_sector: 1024,
            storage_dir: storage_dir.into_path(),
        },
        hmac_system_key: [1; 64],
        hmac_client_key,
    };
    let config2 = Configuration{
        public: PublicConfiguration {
            tcp_locations: vec![("127.0.0.1".to_string(), tcp_port), ("127.0.0.1".to_string(), tcp_port2)],
            self_rank: 2,
            max_sector: 1024,
            storage_dir: storage_dir2.into_path(),
        },
        hmac_system_key: [1; 64],
        hmac_client_key,
    };

    tokio::spawn(run_register_process(config));
    tokio::spawn(run_register_process(config2));

    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut stream = TcpStream::connect(("127.0.0.1", tcp_port))
        .await
        .expect("Could not connect to TCP port");
    let mut stream2 = TcpStream::connect(("127.0.0.1", tcp_port2))
        .await.expect("couldnt connect to tcp port");

    for i in 0..N{
        let write_cmd = RegisterCommand::Client(ClientRegisterCommand {
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
        let write_cmd = RegisterCommand::Client(ClientRegisterCommand {
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

        assert_eq!(&buf[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf[7], 0x42);
        all_ids.insert(u64::from_be_bytes(buf[8..16].try_into().unwrap()));

        assert!(hmac_tag_is_ok(&hmac_client_key, &buf));
        println!("ITERATION {:?} IS CORRENT! WELL DONE", i);
    }
    for i in 0..(2 * N) {
        assert!(all_ids.contains(&(request_identifier + i)));
    }

    // when
    for i in 0..N {
        let read_cmd = RegisterCommand::Client(ClientRegisterCommand {
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
    for _ in 0..N {
        let mut buf2: Vec<u8> = vec![0; 4096 + EXPECTED_RESPONSES_SIZE];
        stream2.read_exact(buf2.as_mut_slice())
            .await
            .expect("less data than expected");
        assert_eq!(&buf2[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf2[7], 0x41);
        all_answers.insert(u64::from_be_bytes(buf2[8..16].try_into().unwrap()), buf2[16..4112].to_vec());
        assert!(hmac_tag_is_ok(&hmac_client_key, &buf2));
    }
    for i in 0..N {
        let id = request_identifier + N + N + i;
        assert!(all_answers.contains_key(&id));
        assert_eq!(all_answers.get(&id).unwrap(), &vec![(N + i) as u8; 4096].as_slice());
    }
}

#[tokio::test]
#[timeout(45000)]
async fn write_propagates_to_many() {
    const SERVER_COUNT : usize = 10;
    const EXPECTED_RESPONSES_SIZE: usize = 48;
    let hmac_client_key = [5; 32];
    let tcp_port = 32_000;

    let request_identifier = 1778;

    let mut all_tcp_locations = Vec::new();
    for i in 0..SERVER_COUNT {
        all_tcp_locations.push(("127.0.0.1".to_string(), tcp_port + i as u16));
    }

    for i in 0..SERVER_COUNT {
        tokio::spawn(run_register_process(Configuration {
            public: PublicConfiguration {
                tcp_locations: all_tcp_locations.clone(),
                self_rank: (i + 1) as u8,
                max_sector: 1024,
                storage_dir: tempdir().unwrap().into_path(),
            },
            hmac_system_key: [1; 64],
            hmac_client_key,
        }));
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut stream = TcpStream::connect(("127.0.0.1", tcp_port + (SERVER_COUNT as u16 / 3) - 1))
        .await.expect("Could not connect to TCP port");

    let write_cmd = RegisterCommand::Client(ClientRegisterCommand {
        header: ClientCommandHeader {
            request_identifier: request_identifier as u64,
            sector_idx: 42 as u64,
        },
        content: ClientRegisterCommandContent::Write {
            data: SectorVec(vec![43 as u8; 4096]),
        },
    });
    send_cmd(&write_cmd, &mut stream, &hmac_client_key.clone()).await;

    let mut buf = [0_u8; EXPECTED_RESPONSES_SIZE];
    stream
        .read_exact(&mut buf)
        .await
        .expect("Less data then expected");

    assert_eq!(&buf[0..4], MAGIC_NUMBER.as_ref());
    assert_eq!(buf[7], 0x42);
    assert_eq!(
        u64::from_be_bytes(buf[8..16].try_into().unwrap()),
        request_identifier
    );
    assert!(hmac_tag_is_ok(&hmac_client_key, &buf));

    // when
    for i in 0..SERVER_COUNT {
        let read_cmd = RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: request_identifier * 2 + i as u64,
                sector_idx: 42 as u64,
            },
            content: ClientRegisterCommandContent::Read
        });
        // then
        let mut stream2 = TcpStream::connect(("127.0.0.1", tcp_port + i as u16)).await.expect("couldnt connect to tcp port");

        send_cmd(&read_cmd, &mut stream2, &hmac_client_key.clone()).await;
        let mut buf2: Vec<u8> = vec![0; 4096 + EXPECTED_RESPONSES_SIZE];
        stream2.read_exact(buf2.as_mut_slice())
            .await
            .expect("less data than expected");
        assert_eq!(&buf2[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf2[7], 0x41);
        assert_eq!(
            u64::from_be_bytes(buf2[8..16].try_into().unwrap()),
            (request_identifier * 2 + i as u64)
        );
        assert_eq!(&buf2[16..4112], vec![43 as u8; 4096].as_slice());
        assert!(hmac_tag_is_ok(&hmac_client_key, &buf2));
    }   
}

use rand::seq::SliceRandom;
use rand::thread_rng;
use std::iter::FromIterator;

#[tokio::test]
#[timeout(45000)]
async fn write_races() {
    const SERVER_COUNT : usize = 10;
    const EXPECTED_RESPONSES_SIZE: usize = 48;
    let hmac_client_key = [5; 32];
    let tcp_port = 30_000;

    let request_identifier = 1778;

    let mut all_tcp_locations = Vec::new();
    for i in 0..SERVER_COUNT {
        all_tcp_locations.push(("127.0.0.1".to_string(), tcp_port + i as u16));
    }

    for i in 0..SERVER_COUNT {
        tokio::spawn(run_register_process(Configuration {
            public: PublicConfiguration {
                tcp_locations: all_tcp_locations.clone(),
                self_rank: (i + 1) as u8,
                max_sector: 1024,
                storage_dir: tempdir().unwrap().into_path(),
            },
            hmac_system_key: [1; 64],
            hmac_client_key,
        }));
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut random_perm : Vec<usize> = (0..SERVER_COUNT).collect(); 

    let mut rng = thread_rng();
    random_perm.shuffle(&mut rng);

    for i in &random_perm {
        let read_cmd = RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: (request_identifier + i) as u64,
                sector_idx: 42 as u64,
            },
            content: ClientRegisterCommandContent::Write {
                data: SectorVec(vec![*i as u8; 4096]),
            },
        });
        // then
        let mut stream2 = TcpStream::connect(("127.0.0.1", tcp_port + *i as u16)).await.expect("couldnt connect to tcp port");
        send_cmd(&read_cmd, &mut stream2, &hmac_client_key.clone()).await;
        
        // let mut buf2: Vec<u8> = vec![0; EXPECTED_RESPONSES_SIZE];
        // stream2.read_exact(buf2.as_mut_slice())
        //     .await
        //     .expect("less data than expected");
        // println!("Data read");
        // assert_eq!(&buf2[0..4], MAGIC_NUMBER.as_ref());
        // assert_eq!(buf2[7], 0x42);
        // assert_eq!(
        //     u64::from_be_bytes(buf2[8..16].try_into().unwrap()),
        //     ((request_identifier + i) as u64)
        // );
        // assert!(hmac_tag_is_ok(&hmac_client_key, &buf2));
    }   


    let mut what_was_the_answer = None;
    for i in 0..SERVER_COUNT {
        let read_cmd = RegisterCommand::Client(ClientRegisterCommand {
            header: ClientCommandHeader {
                request_identifier: (request_identifier + SERVER_COUNT + i) as u64,
                sector_idx: 42 as u64,
            },
            content: ClientRegisterCommandContent::Read
        });
        // then

        // then
        let mut stream2 = TcpStream::connect(("127.0.0.1", tcp_port + i as u16)).await.expect("couldnt connect to tcp port");

        send_cmd(&read_cmd, &mut stream2, &hmac_client_key.clone()).await;
        let mut buf2: Vec<u8> = vec![0; 4096 + EXPECTED_RESPONSES_SIZE];
        stream2.read_exact(buf2.as_mut_slice())
            .await
            .expect("less data than expected");
        assert_eq!(&buf2[0..4], MAGIC_NUMBER.as_ref());
        assert_eq!(buf2[7], 0x41);
        assert_eq!(
            u64::from_be_bytes(buf2[8..16].try_into().unwrap()),
            (request_identifier + SERVER_COUNT + i) as u64
        );
        assert_eq!(1, HashSet::<&u8>::from_iter(&mut (buf2[16..4112].iter())).len());
        match what_was_the_answer {
            None => {
                what_was_the_answer = Some(buf2[17]);
            }
            Some(data) => {
                assert_eq!(data, buf2[17]);
                // assert_eq!(data, random_perm.clone()[SERVER_COUNT - 1] as u8);
            }
        }
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
