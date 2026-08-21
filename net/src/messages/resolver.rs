use std::ops::Deref;

use hickory_proto::{
    ProtoError,
    op::{Edns, Query},
};

use super::Message;

/// The request object for a single DNS query.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    query: Query,
    edns: Option<Edns>,
}

impl DnsQuery {
    pub fn new(query: Query, edns: Option<Edns>) -> Self {
        Self { query, edns }
    }

    pub fn extensions(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    pub fn query(&self) -> &Query {
        &self.query
    }

    pub fn into_query(self) -> Query {
        self.query
    }
}

impl From<Query> for DnsQuery {
    fn from(query: Query) -> Self {
        Self { query, edns: None }
    }
}

impl TryFrom<Message> for DnsQuery {
    type Error = ProtoError;

    fn try_from(message: Message) -> Result<Self, Self::Error> {
        let query = message.queries().try_as_query()?.clone();
        let edns = message.extensions().clone();
        Ok(DnsQuery { query, edns })
    }
}

impl Deref for DnsQuery {
    type Target = Query;

    fn deref(&self) -> &Self::Target {
        &self.query
    }
}
