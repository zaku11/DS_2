use assignment_2_solution::{
    deserialize_register_command, serialize_register_command, ClientCommandHeader,
    ClientRegisterCommand, ClientRegisterCommandContent, RegisterCommand,
};
use ntest::timeout;

#[test]
#[timeout(200)]
fn serialize_deserialize_is_identity() {
    // given
    let request_identifier = 7;
    let sector_idx = 8;
    let register_cmd = RegisterCommand::Client(ClientRegisterCommand {
        header: ClientCommandHeader {
            request_identifier,
            sector_idx,
        },
        content: ClientRegisterCommandContent::Read,
    });
    let mut sink: Vec<u8> = Vec::new();

    // when
    serialize_register_command(&register_cmd, &mut sink).expect("Could not serialize?");
    let mut slice: &[u8] = &sink[..];
    let data_read: &mut dyn std::io::Read = &mut slice;
    let deserialized_cmd = deserialize_register_command(data_read).expect("Could not deserialize");

    // then
    match deserialized_cmd {
        RegisterCommand::Client(ClientRegisterCommand {
            header,
            content: ClientRegisterCommandContent::Read,
        }) => {
            assert_eq!(header.sector_idx, sector_idx);
            assert_eq!(header.request_identifier, request_identifier);
        }
        _ => panic!("Expected Read command"),
    }
}
