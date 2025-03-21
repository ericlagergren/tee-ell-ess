use core::ops::Deref;

use crate::{
    server::ServerConfig,
    wire::{vec::Iter, ProtocolVersion},
};

#[derive(Copy, Clone, Debug)]
struct Config<'a>(&'a dyn ServerConfig);

impl Config<'_> {
    // Returns the mutually supported TLS version.
    fn mutual_version(&self, peer: Iter<'_, ProtocolVersion>) -> Option<ProtocolVersion> {
        for pv in peer {
            for v in self.supported_versions() {
                if pv == v.to_wire() {
                    return Some(pv);
                }
            }
        }
        None
    }
}

impl<'a> Deref for Config<'a> {
    type Target = &'a dyn ServerConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
