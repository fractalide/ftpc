use {
    copernica_common::{LinkId, NarrowWaistPacket, LinkPacket, InterLinkPacket, HBFI, serialization::*},
    crate::{Manifest, FileManifest, Protocol, TxRx},
    copernica_identity::{PrivateIdentity},
    crossbeam_channel::{ Sender, Receiver },
    sled::{Db},
    bincode,
    anyhow::{Result, anyhow},
    std::{thread},
    log::{debug},
};
#[derive(Clone)]
pub struct FTP {
    txrx: Option<TxRx>,
}
impl<'a> FTP {
    pub fn manifest(&mut self, hbfi: HBFI) -> Result<Manifest> {
        if let Some(txrx) = self.txrx.clone() {
            let hbfi = hbfi.clone().offset(0);
            let manifest = txrx.request(hbfi.clone(), 0, 0)?;
            let manifest: Manifest = bincode::deserialize(&manifest)?;
            Ok(manifest)
        } else {
            Err(anyhow!("You must peer with a link first"))
        }
    }
    pub fn file_manifest(&mut self, hbfi: HBFI) -> Result<FileManifest> {
        if let Some(txrx) = self.txrx.clone() {
            let manifest: Manifest = self.manifest(hbfi.clone())?;
            let file_manifest = txrx.request(hbfi, manifest.start, manifest.end)?;
            let file_manifest: FileManifest = bincode::deserialize(&file_manifest)?;
            Ok(file_manifest)
        } else {
            Err(anyhow!("You must peer with a link first"))
        }
    }
    pub fn file_names(&mut self, hbfi: HBFI) -> Result<Vec<String>> {
        let file_manifest: FileManifest = self.file_manifest(hbfi.clone())?;
        let mut names: Vec<String> = vec![];
        for (path, _) in file_manifest.files {
            names.push(path);
        }
        Ok(names)
    }
    pub fn file(&mut self, hbfi: HBFI, name: String) -> Result<Vec<u8>> {
        if let Some(txrx) = self.txrx.clone() {
            let file_manifest: FileManifest = self.file_manifest(hbfi.clone())?;
            if let Some((start, end)) = file_manifest.files.get(&name) {
                let file = txrx.request(hbfi.clone(), *start, *end)?;
                return Ok(file);
            }
            return Err(anyhow!("File not present"))
        } else {
            Err(anyhow!("You must peer with a link first"))
        }
    }
}
impl<'a> Protocol<'a> for FTP {
    fn new() -> FTP {
        FTP {
            txrx: None,
        }
    }
    fn run(&mut self) -> Result<()> {
        let txrx = self.txrx.clone();
        thread::spawn(move || {
            if let Some(txrx) = txrx {
                loop {
                    if let Ok(ilp) = txrx.l2p_rx.recv() {
                        debug!("\t\t|  link-to-protocol");
                        let nw: NarrowWaistPacket = ilp.narrow_waist();
                        match nw.clone() {
                            NarrowWaistPacket::Request { hbfi, .. } => {
                                let (_, hbfi_s) = serialize_hbfi(&hbfi)?;
                                if txrx.db.contains_key(hbfi_s.clone())? {
                                    let nw = txrx.db.get(hbfi_s)?;
                                    match nw {
                                        Some(nw) => {
                                            debug!("\t\t|  RESPONSE PACKET FOUND");
                                            let nw = deserialize_narrow_waist_packet(&nw.to_vec())?;
                                            let lp = LinkPacket::new(txrx.link_id.reply_to()?, nw);
                                            let ilp = InterLinkPacket::new(txrx.link_id.clone(), lp);
                                            debug!("\t\t|  protocol-to-link");
                                            txrx.p2l_tx.send(ilp)?;
                                        },
                                        None => {},
                                    }
                                } else {
                                    let hbfi_ctr = hbfi.cleartext_repr();
                                    let (_, hbfi_ctr) = serialize_hbfi(&hbfi_ctr)?;
                                    if txrx.db.contains_key(hbfi_ctr.clone())? {
                                        let nw = txrx.db.get(hbfi_ctr)?;
                                        match nw {
                                            Some(nw) => {
                                                match hbfi.request_pid {
                                                    Some(request_pid) => {
                                                        debug!("\t\t|  RESPONSE PACKET FOUND ENCRYPT IT");
                                                        let nw = deserialize_narrow_waist_packet(&nw.to_vec())?;
                                                        let nw = nw.encrypt_for(request_pid, txrx.sid.clone())?;
                                                        let lp = LinkPacket::new(txrx.link_id.reply_to()?, nw);
                                                        let ilp = InterLinkPacket::new(txrx.link_id.clone(), lp);
                                                        debug!("\t\t|  protocol-to-link");
                                                        txrx.p2l_tx.send(ilp.clone())?;
                                                    },
                                                    None => {
                                                        debug!("\t\t|  RESPONSE PACKET FOUND CLEARTEXT IT");
                                                        let nw = deserialize_narrow_waist_packet(&nw.to_vec())?;
                                                        let lp = LinkPacket::new(txrx.link_id.reply_to()?, nw);
                                                        let ilp = InterLinkPacket::new(txrx.link_id.clone(), lp);
                                                        debug!("\t\t|  protocol-to-link");
                                                        txrx.p2l_tx.send(ilp)?;
                                                    },
                                                }
                                            },
                                            None => {},
                                        }
                                    };
                                }
                            },
                            NarrowWaistPacket::Response { hbfi, .. } => {
                                debug!("\t\t|  RESPONSE PACKET ARRIVED");
                                let (_, hbfi_s) = serialize_hbfi(&hbfi)?;
                                let (_, nw_s) = serialize_narrow_waist_packet(&nw)?;
                                txrx.db.insert(hbfi_s, nw_s)?;
                            },
                        }
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        });
        Ok(())
    }
    fn set_txrx(&mut self, txrx: TxRx) {
        self.txrx = Some(txrx);
    }
    fn get_txrx(&mut self) -> Option<TxRx> {
        self.txrx.clone()
    }
}

