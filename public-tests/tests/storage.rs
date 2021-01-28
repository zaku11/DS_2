use assignment_2_solution::{
    StableStorage, build_stable_storage
};
use ntest::timeout;
use std::path::PathBuf;
use tempfile::tempdir;

use tokio;

#[tokio::test]
#[timeout(400000)]
async fn test_storage() {
    let _ = env_logger::builder().is_test(true).try_init();
    // let storage_dir = PathBuf::new();
    // storage_dir.push("/home/mateusz/dsas2test/"); // tempdir().unwrap();
    // log::info!("stable storage root: {:?}", storage_dir.clone());
    let mut storage = build_stable_storage(tempdir().unwrap().into_path()).await;

    let msg : [u8; 3] = [0x1, 0x2, 0x3];
    storage.put("key", &msg).await.unwrap();
    let res = storage.get("key").await.unwrap();
    assert_eq!(res, msg);
}
