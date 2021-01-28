use assignment_2_solution::{
    deserialize_register_command, serialize_register_command, ClientCommandHeader,
    ClientRegisterCommand, ClientRegisterCommandContent, RegisterCommand, SectorVec
};
use ntest::timeout;
use std::io::BufWriter;
use std::io::BufReader;
use std::io::Read;
use std::fs::File;
use std::io::Cursor;

#[test]
#[timeout(200)]
fn match_all_serialize() {
    // those are fixed
    let request_identifier : u64 = 0xdeadbeef;
    let sector_idx : u64 = 0x1;
    let data = vec![0x61; 4096];
    let data = SectorVec(data);

    let register_cmd_read = RegisterCommand::Client(ClientRegisterCommand {
        header: ClientCommandHeader {
            request_identifier,
            sector_idx,
        },
        content: ClientRegisterCommandContent::Read,
    });

    let register_cmd_write = RegisterCommand::Client(ClientRegisterCommand {
        header: ClientCommandHeader {
            request_identifier,
            sector_idx,
        },
        content: ClientRegisterCommandContent::Write{data},
    });

    let mut read_writer = vec![];
    let mut write_writer = vec![];
    serialize_register_command(&register_cmd_read, &mut read_writer).unwrap();
    serialize_register_command(&register_cmd_write, &mut write_writer).unwrap();

    assert_eq!(read_writer.len(), 24);
    assert_eq!(write_writer.len(), 4120);

    let mut read_writer_ref = vec![];
    let mut write_writer_ref = vec![];
    let mut read_f = File::open("./client_read.bytes").unwrap();
    let mut write_f = File::open("./client_write.bytes").unwrap();
    let maybe_24 = read_f.read_to_end(&mut read_writer_ref).unwrap(); 
    let maybe_4120 = write_f.read_to_end(&mut write_writer_ref).unwrap();
    
    assert_eq!(maybe_24, 24);
    assert_eq!(maybe_4120, 4120);

    assert_eq!(vec![1,2,3], vec![1,2,3]);
    assert_ne!(vec![1,2,3,3], vec![1,2,3]);

    assert_eq!(read_writer, read_writer_ref);
    assert_eq!(write_writer, write_writer_ref);

    // serialization tested - now deserialize..
    let write_cmd_deserialized = deserialize_register_command(&mut BufReader::new(Cursor::new(write_writer))).unwrap();
    let read_cmd_deserialized = deserialize_register_command(&mut BufReader::new(Cursor::new(read_writer))).unwrap();

    assert_eq!(write_cmd_deserialized, register_cmd_write);
    assert_eq!(read_cmd_deserialized, register_cmd_read);
}
