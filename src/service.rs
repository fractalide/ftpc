use {
    copernica_common::{LinkId, InterLinkPacket, HBFI},
    copernica_protocols::{FTP, Protocol},
    std::{thread},
    crossbeam_channel::{Sender, Receiver, unbounded},
    copernica_identity::{PrivateIdentity},
    //sled::{Db, Event},
    anyhow::{Result},
    //log::{debug},
};

#[derive(Clone, Debug)]
enum FTPCommands {
    RequestFileList(HBFI),
    ResponseFileList(Option<Vec<String>>),
    RequestFile(HBFI, String),
    ResponseFile(Option<Vec<u8>>),
}

pub struct FTPService {
    link_id: Option<LinkId>,
    db: sled::Db,
    protocol: FTP,
    sid: PrivateIdentity,
}

impl FTPService {
    pub fn new(db: sled::Db, sid: PrivateIdentity) -> Self {
        let protocol: FTP = Protocol::new();
        Self {
            link_id: None,
            db,
            protocol,
            sid,
        }
    }
    pub fn peer_with_link(
        &mut self,
        link_id: LinkId,
    ) -> Result<(Sender<InterLinkPacket>, Receiver<InterLinkPacket>)> {
        self.link_id = Some(link_id.clone());
        Ok(self.protocol.peer_with_link(self.db.clone(), link_id, self.sid.clone())?)
    }
    pub fn run(&mut self) -> Result<()>{
        let mut protocol = self.protocol.clone();
        protocol.run()?;
        Ok(())
    }
}
