use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
};

use hickory_proto::{
    ProtoError,
    op::{Header, Query},
    rr::Record,
};

use super::{Message, Protocol};

#[derive(Debug, Clone)]
pub struct Incoming<M> {
    message: M,
    address: SocketAddr,
    protocol: Protocol,
}

impl<M> Incoming<M> {
    pub fn new(message: M, address: SocketAddr, protocol: Protocol) -> Self {
        Self {
            message,
            address,
            protocol,
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

impl<M> AsRef<M> for Incoming<M> {
    fn as_ref(&self) -> &M {
        &self.message
    }
}

impl<M> Deref for Incoming<M> {
    type Target = M;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl<M> DerefMut for Incoming<M> {
    fn deref_mut(&mut self) -> &mut M {
        &mut self.message
    }
}

#[derive(Debug, Clone)]
pub struct RequestInfo<'a> {
    /// The source address from which the request came
    pub src: SocketAddr,
    /// The protocol used for the request
    pub protocol: Protocol,
    /// The header from the original request
    pub header: &'a Header,
    /// The query from the request
    pub query: &'a Query,
}

impl Incoming<Message> {
    pub fn request_info(&self) -> Result<RequestInfo<'_>, ProtoError> {
        Ok(RequestInfo {
            src: self.address,
            protocol: self.protocol,
            header: self.message.header(),
            query: self.message.queries().try_as_query()?,
        })
    }
}

/// A type which represents an MessageRequest for dynamic Update.
pub trait UpdateRequest {
    /// Id of the Message
    fn id(&self) -> u16;

    /// Zone being updated, this should be the query of a Message
    fn zone(&self) -> Result<&Query, ProtoError>;

    /// Prerequisites map to the answers of a Message
    fn prerequisites(&self) -> &[Record];

    /// Records to update map to the name_servers of a Message
    fn updates(&self) -> &[Record];

    /// Additional records
    fn additionals(&self) -> &[Record];

    /// SIG0 records for verifying the Message
    fn sig0(&self) -> &[Record];
}

impl UpdateRequest for Message {
    fn id(&self) -> u16 {
        Self::id(self)
    }

    fn zone(&self) -> Result<&Query, ProtoError> {
        // RFC 2136 says "the Zone Section is allowed to contain exactly one record."
        self.queries().try_as_query()
    }

    fn prerequisites(&self) -> &[Record] {
        self.answers()
    }

    fn updates(&self) -> &[Record] {
        self.name_servers()
    }

    fn additionals(&self) -> &[Record] {
        self.additionals()
    }

    fn sig0(&self) -> &[Record] {
        self.sig0()
    }
}
