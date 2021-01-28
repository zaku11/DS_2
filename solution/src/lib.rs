mod domain;

pub use crate::domain::*;
pub use atomic_register_public::*;
pub use register_client_public::*;
pub use sectors_manager_public::*;
pub use stable_storage_public::*;
pub use transfer_public::*;

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::prelude::*;
use tokio::sync::Mutex;

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;
use crate::{RegisterCommand::Client, RegisterCommand::System};

use std::sync::{Arc};
use uuid::Uuid;
use tokio::time::{Duration, interval};


fn does_end_with_magic(v : &Vec<u8>) -> bool {
    if v.len() < 4 {
        return false;
    }
    if v[v.len() - 4] == MAGIC_NUMBER[0] && v[v.len() - 3] == MAGIC_NUMBER[1] && v[v.len() - 2] == MAGIC_NUMBER[2] && v[v.len() - 1] == MAGIC_NUMBER[3] {
        return true;
    }
    return false;
}

// code shift == 1 <=> operation is READ
// code shift == 2 <=> operation is WRITE
fn client_response_to_u8(operation : OperationComplete, code_shift : u8, public_key : [u8;32]) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend(MAGIC_NUMBER.iter()); // MAGIC NUMBER
    for _ in 0..2 {
        buffer.push(0 as u8); // PADDING
    }
    buffer.push(operation.status_code as u8); // STATUS CODE
    buffer.push(code_shift + 0x40); // MSG TYPE
    buffer.extend(operation.request_identifier.to_be_bytes().iter()); // REQUEST NUMBER
    if operation.status_code == StatusCode::Ok {
        match operation.op_return {
            OperationReturn::Write => {},
            OperationReturn::Read(data) => {
                buffer.extend(data.read_data.unwrap().0);
            }
        }
    } // RESPONSE CONTENT
    
    let mut mac = HmacSha256::new_varkey(&public_key).unwrap();
    mac.update(&buffer);
    let hmac_tag = mac.finalize().into_bytes();
    buffer.extend(hmac_tag); // HMAC TAG

    return buffer;
}

fn ack_to_u8(uuid : Uuid, status_code : StatusCode, rank : u8, msg_type : u8) -> Vec<u8> {
    let mut ans = Vec::new();
    ans.extend(MAGIC_NUMBER.iter()); // MAGIC NUMBER
    ans.push(0); // PADDING
    ans.push(status_code as u8); // STATUS CODE
    ans.push(rank); // RANK
    ans.push(msg_type + 0x40); // MSG TYPE
    ans.extend(uuid.as_bytes()); // UUID
    ans
}

const WORKER_COUNT : usize = 256;

pub async fn run_register_process(config: Configuration) {
    // Listening on some port
    let parts = &config.public.tcp_locations[config.public.self_rank as usize - 1];
    let address = parts.0.clone() + ":" + &parts.1.to_string(); 
    let listener = TcpListener::bind(address.clone()).await.unwrap();

    let mut sector_dir = config.public.storage_dir.clone();
    sector_dir.push("sector_manager");
    let sectors_manager = build_sectors_manager(sector_dir);

    let mut workers = Arc::new(Vec::new());

    let register_client = build_register_client(config.hmac_system_key, config.public.tcp_locations.clone());

    for i in 0..WORKER_COUNT {
        let mut path_to_another_register = config.public.storage_dir.clone();
        path_to_another_register.push(i.to_string());
        let stab_stor = build_stable_storage(path_to_another_register).await;

        let (register, _) = build_my_atomic_register(config.public.self_rank, stab_stor, register_client.clone() , sectors_manager.clone(), config.public.tcp_locations.len()).await;

        Arc::get_mut(&mut workers).unwrap().push(Arc::new(Mutex::new(register)));
    }
    // Here we will spawn a proccess that is responsible for resending messages which were possibly not delivered to the other process 
    let pkey = config.hmac_client_key.clone();
    let max_sector = config.public.max_sector;
    let reg_clone = register_client.clone();

    tokio::spawn(async move {
        let mut interval = interval(Duration::from_millis(500));
        loop {
            interval.tick().await;
            // I'm doing it this way so we will not deadlock on send
            
            let mut messages = Vec::new();
            {
                let inside = &*reg_clone.unanswered_messages.lock().await;
                for (key, message) in &*inside {
                    messages.push((key.clone(), message.clone()));
                }
            }
            for (_, message) in &*messages {
                reg_clone.send(message.clone()).await;
            }
        }
    });


    loop {
        let (socket, _) = listener.accept().await.unwrap();

        let workers_clone = workers.clone();
        let sender_clone = register_client.clone();
        let public_key = pkey.clone();
        let system_key = config.hmac_system_key.clone();
        let rank = config.public.self_rank;

        // Process each socket concurrently.
        tokio::spawn(async move {
            let socket_std = socket.into_std().unwrap();
            let socket_cloned = socket_std.try_clone().unwrap();
            let mut copied_socket = TcpStream::from_std(socket_cloned).unwrap();

            loop {
                let mut trash : Vec<u8> = Vec::new();
                while !does_end_with_magic(&trash) {
                    let mut new_byte = [0 as u8];
                    match copied_socket.read_exact(&mut new_byte).await {
                        Ok(_) => {}
                        Err(_) => {
                            return;
                        }
                    }; 
                    trash.push(new_byte[0]);
                }       
                let mut rest = [0 as u8; 4]; 
                copied_socket.read_exact(&mut rest).await.unwrap();
                
                let mut whole_msg : Vec<u8> = Vec::new();
                whole_msg.extend(MAGIC_NUMBER.iter());
                whole_msg.extend(rest.iter());
                let msg_type = rest[3];
                match msg_type { // MSG TYPE
                    1 => { // READ
                        let mut rest_of_the_message = [0 as u8; 8 + 8];
                        copied_socket.read_exact(&mut rest_of_the_message).await.unwrap();        
                        whole_msg.extend(rest_of_the_message.iter());
                    }
                    2 => { // WRITE
                        let mut rest_of_the_message = [0 as u8; 8 + 8 + 4096];
                        copied_socket.read_exact(&mut rest_of_the_message).await.unwrap();        
                        whole_msg.extend(rest_of_the_message.iter());
                    }
                    3 => { // READ_PROC
                        let mut rest_of_the_message = [0 as u8; 16 + 8 + 8];
                        copied_socket.read_exact(&mut rest_of_the_message).await.unwrap();        
                        whole_msg.extend(rest_of_the_message.iter());
                    }
                    4 => { // VALUE
                        let mut rest_of_the_message = [0 as u8; 16 + 8 + 8 + 8 + 8 + 4096];
                        copied_socket.read_exact(&mut rest_of_the_message).await.unwrap();        
                        whole_msg.extend(rest_of_the_message.iter());
                    }
                    5 => { // WRITE_PROC
                        let mut rest_of_the_message = [0 as u8; 16 + 8 + 8 + 8 + 8 + 4096];
                        copied_socket.read_exact(&mut rest_of_the_message).await.unwrap();        
                        whole_msg.extend(rest_of_the_message.iter());
                    }
                    6 => { // ACK
                        let mut rest_of_the_message = [0 as u8; 16 + 8 + 8];
                        copied_socket.read_exact(&mut rest_of_the_message).await.unwrap();        
                        whole_msg.extend(rest_of_the_message.iter());
                    }
                    0x43 | 0x44 | 0x45 | 0x46 => { // SOME FORM OF ACKNOWLEDGEMENT;
                        let mut rest_of_the_message = [0 as u8; 16];
                        copied_socket.read_exact(&mut rest_of_the_message).await.unwrap();        
                        whole_msg.extend(rest_of_the_message.iter());

                        let mut supposed_hmac = [0 as u8; 32];
                        copied_socket.read_exact(&mut supposed_hmac).await.unwrap();

                        let mut mac = HmacSha256::new_varkey(&system_key).unwrap();
                        mac.update(&whole_msg);

                        if mac.verify(supposed_hmac.as_ref()).is_ok() {
                            sender_clone.unanswered_messages.lock().await.remove(&(rest[2], msg_type - 0x40, Uuid::from_bytes(rest_of_the_message))); // rank, type, uuid
                        }
                        continue;
                    }
                    _ => { 
                        continue;
                    }
                }
                let mut supposed_hmac = [0 as u8; 32];
                copied_socket.read_exact(&mut supposed_hmac).await.unwrap();

                let mut mac = HmacSha256::new_varkey(&public_key).unwrap();
                mac.update(&whole_msg);
                let mut msg_as_array : &[u8] = &whole_msg;
                let cmd = deserialize_register_command(&mut msg_as_array);
                match cmd {
                    Ok(Client(client_cmd)) => {
                        let req_id = client_cmd.header.request_identifier;
                        if !mac.verify(supposed_hmac.as_ref()).is_ok() {
                            copied_socket.write_all(&client_response_to_u8(OperationComplete {
                                status_code : StatusCode::AuthFailure,
                                request_identifier : req_id,
                                op_return : (match msg_type {
                                    1 => OperationReturn::Read(ReadReturn{read_data : None}),
                                    _ => OperationReturn::Write,
                                }) 
                            }, 
                            msg_type, public_key)).await.unwrap();
                            continue;
                        }
                        if client_cmd.header.sector_idx >= max_sector {
                            copied_socket.write_all(&client_response_to_u8(OperationComplete {
                                status_code : StatusCode::InvalidSectorIndex,
                                request_identifier : req_id,
                                op_return : (match msg_type {
                                    1 => OperationReturn::Read(ReadReturn{read_data : None}),
                                    _ => OperationReturn::Write,
                                }) 
                            }, 
                            msg_type, public_key)).await.unwrap();
                            continue;
                        } 
                        let sector_id = client_cmd.header.sector_idx;
                        let index = sector_id as usize % WORKER_COUNT;
                        let which_register = workers_clone.get(index).unwrap();

                        let notifier;
                        {
                            let mut lock = which_register.lock().await;
                            if !lock.metadata.contains_key(&sector_id) {
                                lock.generate_metadata(sector_id).await;
                            }
                            let normal = &lock.metadata.get(&sector_id).unwrap().notifier;
                            notifier = normal.clone();
                        }
                        notifier.notified().await;
                        
                        println!("-------------WE'RE INVOKING CLIENT COMMAND-------------");
                        let mut socket_super_cloned = socket_std.try_clone().unwrap();
                        which_register.lock().await.client_command(client_cmd, Box::new(
                            move |op_complete| {
                                println!("--------------CALLBACK INVOKED--------------");
                                socket_super_cloned.write_all(&client_response_to_u8(op_complete, msg_type, public_key)).unwrap();
                                notifier.notify_one();
                            }
                        )).await;

                    },
                    Ok(System(system_cmd)) => {
                        let index = system_cmd.header.sector_idx as usize % WORKER_COUNT;
                        let target = system_cmd.header.process_identifier.clone() as usize;
                        let which_register = workers_clone.get(index).unwrap(); 

                        let uuid = system_cmd.header.msg_ident.clone();
                        {                        
                            let mut lock = which_register.lock().await;
                            lock.system_command(system_cmd).await;
                        }
                        // After that we need to write ackowledgement
                        sender_clone.send_raw_bytes_no_ack(ack_to_u8(uuid, StatusCode::Ok, rank, msg_type), target).await;
                    },
                    Err(_) => {},
                }
            }
        });
    } 

}

const EMPTY_ANS : [u8; 4096] = [0 as u8; 4096];
fn empty_ans() -> SectorVec {
    SectorVec(EMPTY_ANS.to_vec())
}


pub mod atomic_register_public {
    use crate::{
        ClientRegisterCommand, OperationComplete, RegisterClient, SectorsManager, StableStorage,
        SystemRegisterCommand, ClientCommandHeader, ClientRegisterCommandContent, SystemRegisterCommandContent, Broadcast, SystemCommandHeader, SectorVec, Send as SendStruct,StatusCode, OperationReturn, ReadReturn, empty_ans, ClientRegisterCommandContent::Write as RedefWrite, ClientRegisterCommandContent::Read as RedefRead
    };
    use std::sync::Arc;
    use uuid::Uuid;
    use std::collections::{HashMap, HashSet};
    use tokio::sync::{Notify};

    #[async_trait::async_trait]
    pub trait AtomicRegister: core::marker::Send + core::marker::Sync {
        /// Send client command to the register. After it is completed, we expect
        /// callback to be called. Note that completion of client command happens after
        /// delivery of multiple system commands to the register, as the algorithm specifies.
        async fn client_command(
            &mut self,
            cmd: ClientRegisterCommand,
            operation_complete: Box<dyn FnOnce(OperationComplete) + Send + Sync>,
        );

        /// Send system command to the register.
        async fn system_command(&mut self, cmd: SystemRegisterCommand);
    }
    pub struct AtomicRegisterMetadata {
        ts : u64,
        wr : u8,
        val : SectorVec,
        
        rid : u64,
        readlist : HashMap <u8, (u64, u8, SectorVec)>, // Timestamp, rank, value
        acklist : HashSet<u8>,
        reading : bool,
        writing : bool,
        write_val : SectorVec,
        read_val : SectorVec,
        pub notifier : Arc<Notify>,
    }

    pub struct MyAtomicRegister {
        proc_count : usize,
        register_client : Arc <dyn RegisterClient>,
        id : u8,

        stable_storage : Box <dyn StableStorage>,
        sector_manager : Arc <dyn SectorsManager>,
        callbacks : HashMap<(u64, u64), Box<dyn FnOnce(OperationComplete) + Send + Sync> >,
        request_ids : HashMap<(u64, u64), u64>,
        pub metadata : HashMap<u64, AtomicRegisterMetadata>,
    }
    
    impl MyAtomicRegister {
        fn incr_rid(&mut self, idx : u64) {
            self.metadata.get_mut(&idx).unwrap().rid += 1 as u64;
        }
        pub async fn generate_metadata(&mut self, idx : u64) {
            let (ts, wr) = self.sector_manager.read_metadata(idx).await;
            let val = self.sector_manager.read_data(idx).await;
            self.metadata.insert(idx, AtomicRegisterMetadata {
                ts,
                wr,
                val,

                rid : 0,
                readlist : HashMap::new(),
                acklist : HashSet::new(),
                reading : false,
                writing : false,
                write_val : empty_ans(),  
                read_val : empty_ans(),
                notifier : Arc::new(Notify::new()),
            });
            self.metadata.get(&idx).unwrap().notifier.notify_one();
            let mut all_sectors = Vec::new();
            for (key, _) in &self.metadata {
                all_sectors.push(key);
            }
            self.stable_storage.put("all_sectors", &bincode::serialize(&all_sectors).unwrap()).await.unwrap();
        }
    }

    fn u8_to_bool(x : u8) -> bool {
        if x == 0 {
            return false;
        } else {
            return true;
        }
    }
    fn bool_to_u8(x : bool) -> u8 {
        if x == false {
            return 0;
        } else {
            return 1;
        }
    }


    fn highest(readlist : &HashMap <u8, (u64, u8, SectorVec)>) -> (u64, u8, SectorVec) {
        let mut high_ts = 0 as u64;
        let mut high_rr = 0 as u8;
        let mut high_val : SectorVec = SectorVec(Vec::new());
        let mut first_iter = true;
        for (_, val) in readlist {
            let ts = val.0;
            let rr = val.1;
            if ts > high_ts || (ts == high_ts && rr > high_rr) || first_iter {
                high_ts = ts;
                high_rr = rr;
                high_val = val.2.clone();
            }
            first_iter = false;
        }
        (high_ts, high_rr, high_val)
    } 

    fn vec_to_arr8(vec : Vec<u8>) -> Option<[u8; 8]> {
        if vec.len() != 8 {
            return None;
        }
        let mut arr = [0 as u8; 8];
        for i in 0..8 {
            arr[i] = vec[i];
        }
        return Some(arr);
    }

    impl MyAtomicRegister {
        async fn restore_and_get(&mut self) -> Option<ClientRegisterCommand> {
            let maybe_sectors = self.stable_storage.get("all_sectors").await;
            match maybe_sectors {
                Some(all_sectors_serialized) => {
                    let all_sectors : Vec <u64> = bincode::deserialize(&all_sectors_serialized).unwrap();

                    let mut writing = false;
                    let mut write_data = Vec::new();

                    for sector in all_sectors {
                        let maybe_rid = self.stable_storage.get(&("rid_".to_owned() + &sector.to_string())).await;
                        match maybe_rid {
                            Some(data) => {
                                match vec_to_arr8(data) {
                                    Some(arr) => {self.metadata.get_mut(&sector).unwrap().rid = u64::from_be_bytes(arr);},
                                    _ => {}
                                }
                            },
                            _ => {}
                        }

                        let maybe_write_val = self.stable_storage.get(&("write_val_".to_owned() + &sector.to_string())).await;
                        match maybe_write_val {
                            Some(data) => {
                                self.metadata.get_mut(&sector).unwrap().write_val = SectorVec(data.clone());
                                write_data = data;
                            },
                            _ => {}
                        }

                        let maybe_writing = self.stable_storage.get(&("writing_".to_owned() + &sector.to_string())).await;
                        match maybe_writing {
                            Some(data) => {
                                self.metadata.get_mut(&sector).unwrap().writing = u8_to_bool(data[0]); 
                                writing = true
                            },
                            _ => {}
                        }   
                    }
                    match self.stable_storage.get("current_cmd_header").await {
                        Some(data) => {
                            if data.len() == 0 {
                                return None;
                            }
                            let decoded : ClientCommandHeader = bincode::deserialize(&data).unwrap();
                            if writing {
                                return Some(ClientRegisterCommand {
                                    header : decoded,
                                    content : RedefWrite {
                                        data : SectorVec(write_data),
                                    }
                                });
                            } else {
                                return Some(ClientRegisterCommand {
                                    header : decoded,
                                    content : RedefRead
                                });
                            }
                        }
                        _ => {return None;}
                    }
                }
                _ => {return None;}
            }
        }
    }

    #[async_trait::async_trait]
    impl AtomicRegister for MyAtomicRegister {
        async fn client_command(
            &mut self,
            cmd: ClientRegisterCommand,
            operation_complete: Box<dyn FnOnce(OperationComplete) + Send + Sync>,
        ) {
            let ClientCommandHeader {
                request_identifier : req_id,
                sector_idx : sector_id,
            } = cmd.header;
    
            if !self.metadata.contains_key(&sector_id) {
                self.generate_metadata(sector_id).await;
            }

            self.incr_rid(sector_id);

            let current_rid = self.metadata.get(&sector_id).unwrap().rid;
            self.callbacks.insert((sector_id, current_rid), operation_complete);
            self.request_ids.insert((sector_id, current_rid), req_id);
            
            let this_sector = self.metadata.get_mut(&sector_id).unwrap();

            this_sector.readlist = HashMap::new();
            this_sector.acklist = HashSet::new();

            let new_hdr = SystemCommandHeader {
                process_identifier : self.id,
                msg_ident : Uuid::new_v4(),
                read_ident : current_rid,
                sector_idx : sector_id,
            };

            match cmd.content {
                ClientRegisterCommandContent::Read => {
                    this_sector.reading = true;
                    self.stable_storage.put(&("rid_".to_owned() + &sector_id.to_string()), &self.metadata.get(&sector_id).unwrap().rid.to_be_bytes()).await.unwrap();

                    self.register_client.broadcast(Broadcast {
                        cmd : Arc::new(SystemRegisterCommand {
                            header : new_hdr,
                            content : SystemRegisterCommandContent::ReadProc,
                        })
                    }).await
                },
                ClientRegisterCommandContent::Write{data} => {
                    this_sector.write_val = data.clone();
                    this_sector.writing = true;
                    let cmd_serded = bincode::serialize(&cmd.header).unwrap();


                    self.stable_storage.put(&("current_cmd_header_"), &cmd_serded).await.unwrap();
                    self.stable_storage.put(&("rid_".to_owned() + &sector_id.to_string()), &this_sector.rid.to_be_bytes()).await.unwrap();
                    self.stable_storage.put(&("write_val_".to_owned() + &sector_id.to_string()), &data.clone().0).await.unwrap();
                    self.stable_storage.put(&("writing_".to_owned() + &sector_id.to_string()), &[bool_to_u8(true)]).await.unwrap();

                    self.register_client.broadcast(Broadcast {
                        cmd : Arc::new(SystemRegisterCommand {
                            header : new_hdr,
                            content : SystemRegisterCommandContent::ReadProc,
                        })
                    }).await;
                },
            }
        }

        async fn system_command(&mut self, cmd: SystemRegisterCommand) {
            let SystemCommandHeader {
                process_identifier : proc_id, // id of the one that invoked the function
                msg_ident : msg_uuid,
                read_ident : rid_of_cmd,
                sector_idx : sector_id,
            } = cmd.header;

            if !self.metadata.contains_key(&sector_id) {
                self.generate_metadata(sector_id).await;
            }
            let this_sector = self.metadata.get_mut(&sector_id).unwrap();

            match cmd.content {
                SystemRegisterCommandContent::ReadProc => {
                    self.register_client.send(SendStruct {
                        cmd : Arc :: new(SystemRegisterCommand {
                            header : SystemCommandHeader {
                                process_identifier : self.id,
                                msg_ident : msg_uuid, // ???
                                read_ident : rid_of_cmd,
                                sector_idx : sector_id,
                            },
                            content : SystemRegisterCommandContent::Value {
                                timestamp : this_sector.ts, 
                                write_rank : this_sector.wr, 
                                sector_data : this_sector.val.clone(), 
                            },
                        }),
                        target : proc_id as usize,
                    }).await;
                },

                SystemRegisterCommandContent::Value{timestamp, write_rank, sector_data} => {
                    if rid_of_cmd == this_sector.rid {
                        this_sector.readlist.insert(proc_id, (timestamp, write_rank, sector_data));
                        if this_sector.readlist.len() > self.proc_count / 2 && (this_sector.reading || this_sector.writing) {
                            let (maxts, rr, readval) = highest(&this_sector.readlist); 
                            this_sector.read_val = readval.clone();
                            this_sector.readlist = HashMap::new();
                            this_sector.acklist = HashSet::new();
                            let hdr = SystemCommandHeader {
                                process_identifier : self.id,
                                msg_ident : msg_uuid, // ???
                                read_ident : rid_of_cmd, //  == self.rid
                                sector_idx : sector_id,
                            };
                            if this_sector.reading {
                                self.register_client.broadcast(Broadcast {
                                    cmd : Arc::new(SystemRegisterCommand {
                                        header : hdr,
                                        content : SystemRegisterCommandContent::WriteProc {
                                            data_to_write : readval, 
                                            timestamp : maxts,
                                            write_rank : rr,
                                        } // == highest(self.readlist)
                                    })
                                }).await;
                            }
                            else {
                                self.register_client.broadcast(Broadcast {
                                    cmd : Arc::new(SystemRegisterCommand {
                                        header : hdr,
                                        content : SystemRegisterCommandContent::WriteProc {
                                            data_to_write : this_sector.write_val.clone(), 
                                            timestamp : maxts + 1,
                                            write_rank : self.id,
                                        }
                                    })
                                }).await;
                            }
                        }
                    }
                },

                SystemRegisterCommandContent::WriteProc{timestamp, write_rank, data_to_write} => {
                    // let (my_ts, my_wr) = self.sector_manager.read_metadata(sector_id).await;
                    let my_ts = this_sector.ts;
                    let my_wr = this_sector.wr;

                    if timestamp > my_ts || (timestamp == my_ts && write_rank > my_wr) {
                        this_sector.ts = timestamp;
                        this_sector.wr = write_rank;
                        this_sector.val = data_to_write.clone();

                        self.sector_manager.write(sector_id, &(data_to_write, timestamp, write_rank)).await;
                    }
                    self.register_client.send(SendStruct {
                        cmd : Arc :: new(SystemRegisterCommand {
                            header : SystemCommandHeader {
                                process_identifier : self.id,
                                msg_ident : msg_uuid, // ???
                                read_ident : rid_of_cmd,
                                sector_idx : sector_id,
                            },
                            content : SystemRegisterCommandContent::Ack,
                        }),
                        target : proc_id as usize,
                    }).await;
                },
                SystemRegisterCommandContent::Ack => {
                    if rid_of_cmd == this_sector.rid {
                        this_sector.acklist.insert(proc_id);
                        if this_sector.acklist.len() > self.proc_count / 2 
                        && (this_sector.reading || this_sector.writing) {
                            this_sector.acklist.clear();
                            let func_to_call = self.callbacks.remove_entry(&(sector_id, rid_of_cmd)).unwrap().1; 
                            if this_sector.reading {
                                this_sector.reading = false;
                                self.stable_storage.put("current_cmd_header", &Vec::new()).await.unwrap();
                                let operation = OperationComplete {
                                    status_code : StatusCode::Ok,
                                    request_identifier : *self.request_ids.get(&(sector_id, this_sector.rid)).unwrap(),
                                    op_return : OperationReturn::Read(ReadReturn {
                                        read_data : Some(this_sector.read_val.clone()),
                                    }),
                                };
                                func_to_call(operation.clone());
                            }
                            else {
                                this_sector.writing = false;
                                self.stable_storage.put("current_cmd_header", &Vec::new()).await.unwrap();
                                self.stable_storage.put(&("writing_".to_owned() + &sector_id.to_string()), &[bool_to_u8(false)]).await.unwrap();

                                let operation = OperationComplete {
                                    status_code : StatusCode::Ok,
                                    request_identifier : *self.request_ids.get(&(sector_id, this_sector.rid)).unwrap(),
                                    op_return : OperationReturn::Write,
                                };
                                func_to_call(operation.clone());
                            }
                            // self.metadata.get(&sector_id).unwrap().notifier.notify_one();
                        }
                    }
                },
            }
        }

    }

    /// Idents are numbered starting at 1 (up to the number of processes in the system).
    /// Storage for atomic register algorithm data is separated into StableStorage.
    /// Communication with other processes of the system is to be done by register_client.
    /// And sectors must be stored in the sectors_manager instance.
    pub async fn build_my_atomic_register(
        self_ident: u8,
        metadata: Box<dyn StableStorage>,
        register_client: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        processes_count: usize,
    ) -> (Box<MyAtomicRegister>, Option<ClientRegisterCommand>) {
        let mut register = Box::new(MyAtomicRegister {
            // rid : self_ident as u64,
            // readlist : HashMap::new(),
            // acklist : HashSet::new(),
            // reading : false,
            // writing : false,
            // write_val : empty_ans(),  
            // read_val : empty_ans(),
            metadata :  HashMap::new(),
            proc_count : processes_count,
            register_client : register_client,
            id : self_ident,
            stable_storage : metadata,
            sector_manager : sectors_manager,
            callbacks : HashMap::new(),
            request_ids : HashMap::new(), 
        });
        let possible_operation = register.restore_and_get().await;
        (register, possible_operation)
    }

    pub async fn build_atomic_register(self_ident: u8,
        metadata: Box<dyn StableStorage>,
        register_client: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        processes_count: usize,
    ) -> (Box<dyn AtomicRegister>, Option<ClientRegisterCommand>) {
        let (register, possible_operation) = build_my_atomic_register(self_ident, metadata, register_client, sectors_manager, processes_count).await;
        (register, possible_operation)
    }
}

pub mod sectors_manager_public {
    use std::sync::Arc;
    use crate::{SectorIdx, SectorVec, empty_ans};
    use std::path::PathBuf;
    use tokio::fs::*;
    use tokio::sync::Semaphore;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    #[async_trait::async_trait]
    pub trait SectorsManager: Send + Sync {
        /// Returns 4096 bytes of sector data by index.
        async fn read_data(&self, idx: SectorIdx) -> SectorVec;

        /// Returns timestamp and write rank of the process which has saved this data.
        /// Timestamps and ranks are relevant for atomic register algorithm, and are described
        /// there.
        async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8);

        /// Writes a new data, along with timestamp and write rank to some sector.
        async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8));
    }

    pub struct MyManager {
        root_path : PathBuf,
        uniqueness_control : Arc<Mutex<HashMap<SectorIdx, Arc<Semaphore>>>>,
    }

    #[async_trait::async_trait]
    impl SectorsManager for MyManager {
        async fn read_data(&self, idx: SectorIdx) -> SectorVec {
            let mut path = self.root_path.clone();
            path.push(idx.to_string());
            
            if !path.exists() {
                return empty_ans();
            }

            let task = read(path).await;
            match task {
                Ok(content) => SectorVec(content),
                Err(_) => empty_ans(),
            }
        }
        async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8) {
            let mut path = self.root_path.clone();
            path.push("metadata");
            path.push(idx.to_string() + "_meta");
            
            if !path.exists() {
                return (0 as u64, 0 as u8);
            }
            let task = read(path).await;
            match task {
                Ok(content) => {
                    let decoded : (u64, u8) = bincode::deserialize(&content).unwrap();
                    return decoded;
                },
                Err(_) => (0 as u64, 0 as u8),
            }

        }
        async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8)) {
            let (data, ts, rank) = sector;
            let mut path = self.root_path.clone();
            path.push(idx.to_string());
            let SectorVec(actual_data) = data;

            let mut path_to_tmp = self.root_path.clone();

            create_dir_all(path_to_tmp.clone()).await.unwrap();
            path_to_tmp.push(idx.to_string() + "_tmp");
            {
                let mut lock = self.uniqueness_control.lock().await;
                if !lock.contains_key(&idx) {
                    lock.insert(idx, Arc::new(Semaphore::new(1)));
                }
            }

            {
                let semaph;
                {
                    let lock = self.uniqueness_control.lock().await;
                    semaph = lock.get(&idx).unwrap().clone();    
                }
                let _permit = semaph.acquire();

                write(path_to_tmp.clone(), actual_data).await.unwrap();
                (File::open(path_to_tmp.clone())).await.unwrap().sync_all().await.unwrap();
                rename(path_to_tmp.clone(), path.clone()).await.unwrap();
                path.pop();

                let dir = File::open(path.clone()).await.unwrap();
                dir.sync_data().await.unwrap();

                path.push("metadata");
                if !path.exists() {
                    create_dir_all(path.clone()).await.unwrap();
                }
                path.push(idx.to_string() + "_meta");

                path_to_tmp.pop();
                path_to_tmp.push("metadata");
                path_to_tmp.push(idx.to_string() + "_meta" + "_tmp");

                write(path_to_tmp.clone(), bincode::serialize(&(ts, rank)).unwrap()).await.unwrap();
                rename(path_to_tmp, path).await.unwrap();
            }
        }
    }

    /// Path parameter points to a directory to which this method has exclusive access.
    pub fn build_sectors_manager(path: PathBuf) -> Arc<dyn SectorsManager> {
        Arc::new(MyManager {
            root_path : path,
            uniqueness_control : Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

/// Your internal representation of RegisterCommand for ser/de can be anything you want,
/// we just would like some hooks into your solution to asses where the problem is, should
/// there be a problem.
pub mod transfer_public {
    use crate::{RegisterCommand, MAGIC_NUMBER, RegisterCommand::Client, RegisterCommand::System, ClientRegisterCommandContent::Write as WriteRedef, ClientRegisterCommandContent::Read as ReadRedef, ClientRegisterCommand, ClientCommandHeader, SystemCommandHeader, SystemRegisterCommandContent::Ack, SystemRegisterCommandContent::ReadProc, SystemRegisterCommandContent::Value, SystemRegisterCommandContent::WriteProc, SectorVec, SystemRegisterCommand};
    use std::io::{Error, Read, Write, ErrorKind};
    use uuid::Uuid;

    pub fn deserialize_register_command(data: &mut dyn Read) -> Result<RegisterCommand, Error> {
        
        let mut prologue = [0 as u8; 8];
        data.read_exact(&mut prologue).unwrap();
        let msg_type = prologue[3 + 4];
        let proc_id = prologue[2 + 4];

        // FIRST 4 BYTES SHOULD CONTAIN MAGIC_NUMBER
        match msg_type { // MSG TYPE
            1 => { // READ
                let mut msg = [0 as u8; 8 + 8]; // REQ NUMBER + SECTOR IDX
                data.read_exact(&mut msg).unwrap();
                let mut bytes8 = [0 as u8; 8];

                bytes8.clone_from_slice(&msg[0..8]);
                let req_number = u64::from_be_bytes(bytes8);

                bytes8.clone_from_slice(&msg[8..16]);
                let sector_id = u64::from_be_bytes(bytes8);

                let cmd = RegisterCommand::Client(ClientRegisterCommand {
                    header : ClientCommandHeader {
                        request_identifier : req_number,
                        sector_idx : sector_id,
                    },
                    content : ReadRedef,
                });
                return Ok(cmd);
            },
            2 => { // WRITE
                let mut msg = [0 as u8; 8 + 8 + 4096]; // REQ NUMBER + SECTOR IDX + CONTENT
                data.read_exact(&mut msg).unwrap();
                let mut bytes8 = [0 as u8; 8];

                bytes8.clone_from_slice(&msg[0..8]);
                let req_number = u64::from_be_bytes(bytes8);
                bytes8.clone_from_slice(&msg[8..16]);
                let sector_id = u64::from_be_bytes(bytes8);

                let cmd = RegisterCommand::Client(ClientRegisterCommand {
                    header : ClientCommandHeader {
                        request_identifier : req_number,
                        sector_idx : sector_id,
                    },
                    content : WriteRedef{data : SectorVec(msg[16..].to_vec())},
                });
                return Ok(cmd);
            },
            3 | 6 => { // READ PROC || ACK
                let mut msg = [0 as u8; 16 + 8 + 8]; // MSG IDENT + READ IDENT + SECTOR ID
                data.read_exact(&mut msg).unwrap();
                let mut bytes8 = [0 as u8; 8];
                let mut bytes16 = [0 as u8; 16];

                bytes16.clone_from_slice(&msg[0..16]);
                let msg_ident = Uuid::from_bytes(bytes16);

                bytes8.clone_from_slice(&msg[16..24]);
                let read_ident = u64::from_be_bytes(bytes8);

                bytes8.clone_from_slice(&msg[24..32]);
                let sector_id = u64::from_be_bytes(bytes8);

                let cmd = RegisterCommand::System(SystemRegisterCommand {
                    header : SystemCommandHeader {
                        process_identifier : proc_id,
                        msg_ident : msg_ident,
                        read_ident : read_ident,
                        sector_idx : sector_id,
                    },
                    content : match msg_type {
                        3 => ReadProc,
                        _ => Ack,
                    },
                });
                return Ok(cmd);

            },
            4 | 5 => { // VALUE || WRITE PROC 
                let mut msg = [0 as u8; 16 + 8 + 8 + 8 + 8 + 4096]; // MSG IDENT + READ IDENT + SECTOR ID + TIMESTAMP + (PADDING + VALUE WR) + SECTOR DATA
                data.read_exact(&mut msg).unwrap();
                let mut bytes8 = [0 as u8; 8];
                let mut bytes16 = [0 as u8; 16];

                bytes16.clone_from_slice(&msg[0..16]);
                let msg_ident = Uuid::from_bytes(bytes16);

                bytes8.clone_from_slice(&msg[16..24]);
                let read_ident = u64::from_be_bytes(bytes8);

                bytes8.clone_from_slice(&msg[24..32]);
                let sector_id = u64::from_be_bytes(bytes8);

                bytes8.clone_from_slice(&msg[32..40]);
                let timestamp = u64::from_be_bytes(bytes8);
                
                let wr = msg[39 + 8];
                let actual_content = SectorVec(msg[48..].to_vec());

                let cmd = RegisterCommand::System(SystemRegisterCommand {
                    header : SystemCommandHeader {
                        process_identifier : proc_id,
                        msg_ident : msg_ident,
                        read_ident : read_ident,
                        sector_idx : sector_id,
                    },
                    content : match msg_type {
                        4 => Value {
                            timestamp : timestamp,
                            write_rank : wr,
                            sector_data : actual_content,
                        },
                        _ => WriteProc {
                            timestamp : timestamp,
                            write_rank : wr,
                            data_to_write : actual_content,
                        },
                    },
                });
                return Ok(cmd);

            },
            _ => {
                Err(Error::new(ErrorKind::Other, "Unrecognized command"))
            },
        }           
    }

    pub fn cmd_to_u8(cmd : &RegisterCommand) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(MAGIC_NUMBER.iter());
        match cmd {
            Client(client_cmd) => {
                for _ in 0..3 {
                    buffer.push(0 as u8);   // PADDING
                }
                let ClientCommandHeader {
                    request_identifier : req_id,
                    sector_idx : sector_id,
                } = client_cmd.header;
                match &client_cmd.content {
                    ReadRedef => {buffer.push((1 as u8).to_be_bytes()[0]);}, // MSG_TYPE
                    WriteRedef{..} => {buffer.push(2 as u8);}   // MSG_TYPE,
                }
                buffer.extend(req_id.to_be_bytes().iter());
                buffer.extend(sector_id.to_be_bytes().iter());
                match &client_cmd.content {
                    WriteRedef{data} => {buffer.extend(data.0.iter());}   // COMMAND_CONTENT,
                    _ => {}
                }
            },
            System(system_cmd) => {
                for _ in 0..2 {
                    buffer.push(0 as u8);   // PADDING
                }

                let SystemCommandHeader {
                    process_identifier : proc_id,
                    msg_ident,
                    read_ident : rid,
                    sector_idx : sector_id,
                } = system_cmd.header;
                buffer.push(proc_id); // PROCESS RANK ?
                match &system_cmd.content {
                    ReadProc => buffer.push(3),
                    Value{..} => buffer.push(4),
                    WriteProc{..} => buffer.push(5),
                    Ack => buffer.push(6),
                } // MSG TYPE

                buffer.extend(msg_ident.as_bytes().iter()); // UUID
                buffer.extend(rid.to_be_bytes().iter()); // READ IDENTIFIER OF REGISTER OPERATION 
                buffer.extend(sector_id.to_be_bytes().iter()); // SECTOR INDEX

                match &system_cmd.content {
                    Value{timestamp, write_rank, sector_data} => {
                        buffer.extend(timestamp.to_be_bytes().iter()); // TIMESTAMP
                        for _ in 0..7 {
                            buffer.push(0); // PADDING;
                        }   
                        buffer.push(*write_rank); // VALUE WR
                        buffer.extend(sector_data.0.iter()); // SECTOR DATA
                    },
                    WriteProc{timestamp, write_rank, data_to_write} => {
                        buffer.extend(timestamp.to_be_bytes().iter()); // TIMESTAMP
                        for _ in 0..7 {
                            buffer.push(0); // PADDING;
                        }   
                        buffer.push(*write_rank); // VALUE WR
                        buffer.extend(data_to_write.0.iter()); // SECTOR DATA
                    },
                    ReadProc => {},
                    Ack => {},
                }
            }
        }
        buffer
    }

    pub fn serialize_register_command(
        cmd: &RegisterCommand,
        writer: &mut dyn Write,
    ) -> Result<(), Error> {
        writer.write_all(&cmd_to_u8(cmd))
    }
}

pub mod register_client_public {
    use crate::{SystemRegisterCommand, RegisterCommand, cmd_to_u8, HmacSha256};
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio::io::{AsyncWriteExt};
    use tokio::sync::{Mutex};

    use hmac::{Mac, NewMac};
    use uuid::Uuid;
    use std::collections::HashMap;


    #[async_trait::async_trait]
    /// We do not need any public implementation of this trait. It is there for use
    /// in AtomicRegister. In our opinion it is a safe bet to say some structure of
    /// this kind must appear in your solution.
    pub trait RegisterClient: core::marker::Send + core::marker::Sync {
        /// Sends a system message to a single process.
        async fn send(&self, msg: Send);

        /// Broadcasts a system message to all processes in the system, including self.
        async fn broadcast(&self, msg: Broadcast);
    }

    pub struct MyRegisterClient {
        hmac_system_key: [u8; 64],
        /// Host and port, indexed by identifiers, of every other process.
        tcp_locations: Vec<(String, u16)>,
        pub unanswered_messages : Arc<Mutex<HashMap<(u8, u8, Uuid), Send>>>,
        tcp_streams : Arc<Mutex<HashMap <String, Arc<Mutex<TcpStream>>>>>,
    }
    impl MyRegisterClient {
        pub async fn send_raw_bytes_no_ack(&self, mut msg : Vec<u8>, target : usize) {
            let parts = &self.tcp_locations[target - 1];
            let address = parts.0.clone() + ":" + &parts.1.to_string(); 
            {            
                let mut lock = self.tcp_streams.lock().await;
                if !(*lock).contains_key(&address) {
                    let tcp_stream = TcpStream::connect(&address).await.unwrap();
                    (*lock).insert(address.clone(), Arc::new(Mutex::new(tcp_stream)));
                }
            }
            let mut mac = HmacSha256::new_varkey(&self.hmac_system_key).unwrap();
            mac.update(&msg);
            let hmac_tag = mac.finalize().into_bytes();
            msg.extend(hmac_tag); // HMAC TAG
            let tcp_stream;
            {
                let lock = self.tcp_streams.lock().await;
                tcp_stream = lock.get(&address).unwrap().clone();
            }
            match tcp_stream.lock().await.write_all(&msg).await {
                Ok(_) => {}
                Err(_) => {self.tcp_streams.lock().await.remove(&address);}
            };
        }
    }

    #[async_trait::async_trait]
    impl RegisterClient for MyRegisterClient {

        async fn send(&self, msg: Send) {
            let internal = &*(msg.cmd);
            let cmd = RegisterCommand::System(internal.clone());
            let cmd_serialized = cmd_to_u8(&cmd);
            self.send_raw_bytes_no_ack(cmd_serialized.clone(), msg.target).await;

            self.unanswered_messages.lock().await.insert((msg.target as u8, cmd_serialized[7], msg.cmd.header.msg_ident), msg);
        }

        async fn broadcast(&self, msg: Broadcast) {
            let mut tasks = Vec::new();
            for i in 0..(self.tcp_locations.len()) {
                tasks.push(self.send(Send {
                    cmd : msg.cmd.clone(),
                    target : (i + 1)
                }));
            }
            while !tasks.is_empty() {
                let task = tasks.pop().unwrap();
                task.await;
            }
        }
    }
    pub fn build_register_client(hmac_system_key : [u8; 64], tcp_locations : Vec<(String, u16)>) -> Arc<MyRegisterClient> {
        Arc::new(MyRegisterClient {
            hmac_system_key,
            tcp_locations,
            tcp_streams : Arc::new(Mutex::new(HashMap::new())),
            unanswered_messages : Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub struct Broadcast {
        pub cmd: Arc<SystemRegisterCommand>,
    }

    #[derive(Clone)]
    pub struct Send {
        pub cmd: Arc<SystemRegisterCommand>,
        /// Identifier of the target process. Those start at 1.
        pub target: usize,
    }
}

pub mod stable_storage_public {
    use std::path::PathBuf;
    use std::str;
    pub use std::sync::Arc;
    use tokio::fs::*;
    use tokio::io::AsyncWriteExt;
    use tokio::io::AsyncReadExt;

    /// A helper trait for small amount of durable metadata needed by the register algorithm
    /// itself. Again, it is only for AtomicRegister definition. StableStorage in unit tests
    /// is durable, as one could expect.

    #[async_trait::async_trait]
    pub trait StableStorage: Send + Sync {
        async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String>;

        async fn get(&self, key: &str) -> Option<Vec<u8>>;
    }

    struct MyStableStorage {
        dir : PathBuf,
    }
    fn key_to_path(key : &str) -> PathBuf {
        let v = key.split('/');
        let mut ans = PathBuf::new();
        for part in v {
            ans.push(part);
        }
        ans
    }
    fn transform_key(key : &str) -> String {
        let mut new_key = key.to_owned();
        new_key = "!".to_owned() + &new_key + &"!".to_owned();
        new_key.insert(new_key.len() / 2, '/');
        new_key
    }
    #[async_trait::async_trait]
    impl StableStorage for MyStableStorage {
        async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
            let mut path_to_tmp = self.dir.clone();
            let my_key = transform_key(key); 

            path_to_tmp.push("not_yet_inserted");
            path_to_tmp.push(key_to_path(&my_key));
            create_dir_all(path_to_tmp.clone()).await.unwrap();

            path_to_tmp.push("file");
            let mut file = File::create(path_to_tmp.clone()).await.unwrap();

            file.write_all(value).await.unwrap();
            file.sync_all().await.unwrap();

            let mut path_to_normal = self.dir.clone();
            path_to_normal.push(key_to_path(&my_key));

            create_dir_all(path_to_normal.clone()).await.unwrap();
            
            path_to_normal.push("file");

            rename(path_to_tmp, path_to_normal.clone()).await.unwrap();
            path_to_normal.pop();

            let dir = File::open(path_to_normal).await.unwrap();
            dir.sync_data().await.unwrap();

            Ok(())
        }
        async fn get(&self, key: &str) -> Option<Vec<u8>> {
            let my_key = transform_key(key);

            let mut file_path = self.dir.clone();
            file_path.push(key_to_path(&my_key));
            file_path.push("file");

            if !file_path.is_file() {
                return None;
            }
            
            let mut content = Vec::new();
            let mut file = File::open(file_path).await.unwrap();
            file.read_to_end(&mut content).await.unwrap();

            Some(content)
        }
    }

    pub async fn build_stable_storage(root_storage_dir: PathBuf) -> Box <dyn StableStorage> {
        let mut tmp_path = root_storage_dir.clone();
        tmp_path.push("not_yet_inserted"); // This will be necessary so our put is atomic
        create_dir_all(tmp_path).await.unwrap();
        Box::new(MyStableStorage {
            dir : root_storage_dir,
        })
    }
}
