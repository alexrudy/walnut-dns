use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
};

use bytes::Bytes;
use chateau::client::conn::protocol::framed::Tagged;
use walnut_proto::{
    ProtocolError,
    op::{Message, Metadata, Query},
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder, DecodeError},
};

use super::Protocol;
use walnut_proto::rr::Record;

#[derive(Debug, Clone)]
pub struct Incoming<M> {
    message: M,

    /// The raw bytes of the incoming message
    raw: Bytes,
    // address: SocketAddr,
    // protocol: Protocol,
}

impl<M> Incoming<M> {
    pub fn new(message: M, raw: Bytes) -> Self {
        Self { message, raw }
    }

    pub fn into_inner(self) -> M {
        self.message
    }

    pub fn raw(&self) -> &Bytes {
        &self.raw
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

impl<M> Tagged for Incoming<M>
where
    M: Tagged,
{
    type Tag = <M as Tagged>::Tag;

    fn tag(&self) -> Self::Tag {
        self.message.tag()
    }
}

impl<M> BinEncodable for Incoming<M>
where
    M: BinEncodable,
{
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), ProtocolError> {
        self.message.emit(encoder)
    }
}

impl<'r, M> BinDecodable<'r> for Incoming<M>
where
    M: BinDecodable<'r>,
{
    fn read(
        reader: &mut walnut_proto::serialize::binary::BinDecoder<'r>,
    ) -> Result<Self, DecodeError> {
        let start = reader.index();
        let msg = M::read(reader)?;
        let raw = reader.slice_from(start)?;
        Ok(Incoming {
            message: msg,
            raw: Bytes::copy_from_slice(raw),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub message: Incoming<Message>,
    pub protocol: Protocol,
    pub src: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct RequestInfo<'a> {
    /// The source address from which the request came
    pub src: SocketAddr,
    /// The protocol used for the request
    pub protocol: Protocol,
    /// The header from the original request
    pub header: &'a Metadata,
    /// The query from the request
    pub query: &'a Query,
}

/// A type which represents an MessageRequest for dynamic Update.
pub trait UpdateRequest {
    /// Id of the Message
    fn id(&self) -> u16;

    /// Zone being updated, this should be the query of a Message
    fn zone(&self) -> Result<&Query, ProtocolError>;

    /// Prerequisites map to the answers of a Message
    fn prerequisites(&self) -> &[Record];

    /// Records to update map to the name_servers of a Message
    fn updates(&self) -> &[Record];

    /// Additional records
    fn additionals(&self) -> &[Record];
}

impl UpdateRequest for Message {
    fn id(&self) -> u16 {
        self.metadata.id
    }

    fn zone(&self) -> Result<&Query, ProtocolError> {
        // RFC 2136 says "the Zone Section is allowed to contain exactly one record."
        self.queries
            .first()
            .ok_or_else(|| DecodeError::BadQueryCount(0).into())
    }

    fn prerequisites(&self) -> &[Record] {
        &self.answers
    }

    fn updates(&self) -> &[Record] {
        &self.authorities
    }

    fn additionals(&self) -> &[Record] {
        &self.additionals
    }
}
