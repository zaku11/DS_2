use assignment_2_solution::{
    build_atomic_register, build_sectors_manager, Broadcast, ClientCommandHeader,
    ClientRegisterCommand, ClientRegisterCommandContent, RegisterClient, Send, StableStorage,
};
use async_channel::{unbounded, Sender};
use ntest::timeout;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

#[tokio::test]
#[timeout(200)]
async fn read_triggers_broadcast() {
    // given
    let (tx, rx) = unbounded();
    let root_drive_dir = tempdir().unwrap();
    let (mut register, pending_cmd) = build_atomic_register(
        1,
        Box::new(RamStableStorage::default()),
        Arc::new(DummyRegisterClient::new(tx)),
        build_sectors_manager(root_drive_dir.into_path()),
        1,
    )
    .await;

    // when
    register
        .client_command(
            ClientRegisterCommand {
                header: ClientCommandHeader {
                    request_identifier: 7,
                    sector_idx: 0,
                },
                content: ClientRegisterCommandContent::Read,
            },
            Box::new(|_op_complete| {}),
        )
        .await;

    // then
    assert!(matches!(pending_cmd, None));
    assert!(matches!(rx.recv().await, Ok(ClientMsg::Broadcast(_))));
}

enum ClientMsg {
    Send(Send),
    Broadcast(Broadcast),
}

struct DummyRegisterClient {
    tx: Sender<ClientMsg>,
}

impl DummyRegisterClient {
    fn new(tx: Sender<ClientMsg>) -> Self {
        Self { tx }
    }
}

#[async_trait::async_trait]
impl RegisterClient for DummyRegisterClient {
    async fn send(&self, msg: Send) {
        self.tx.send(ClientMsg::Send(msg)).await.unwrap();
    }

    async fn broadcast(&self, msg: Broadcast) {
        self.tx.send(ClientMsg::Broadcast(msg)).await.unwrap();
    }
}

#[derive(Clone, Default)]
struct RamStableStorage {
    map: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

#[async_trait::async_trait]
impl StableStorage for RamStableStorage {
    async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        let mut map = self.map.lock().unwrap();
        map.insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    async fn get(&self, key: &str) -> Option<Vec<u8>> {
        let map = self.map.lock().unwrap();
        map.get(key).map(Clone::clone)
    }
}
