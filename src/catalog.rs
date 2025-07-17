//! DNS Zone Catalog System
//!
//! This module provides a catalog system for managing DNS zones and handling DNS requests.
//! It integrates with the hickory-dns library to provide a complete DNS server implementation
//! that can handle multiple zones and route requests to the appropriate authority.
//!
//! The catalog system supports:
//! - Zone storage and retrieval
//! - DNS query processing (A, AAAA, CNAME, etc.)
//! - DNS UPDATE operations
//! - EDNS support
//! - DNSSEC awareness
//! - Authoritative and recursive lookups
use std::fmt;
use std::task::{Context, Poll};
use std::{borrow::Borrow, sync::Arc};

use hickory_proto::op::{Edns, Header, LowerQuery, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{LowerName, RecordSet, RecordType};
use hickory_server::authority::{
    AuthLookup, AuthorityObject, EmptyLookup, LookupControlFlow, LookupError, LookupObject,
    LookupOptions, LookupRecords, MessageResponse, MessageResponseBuilder,
};
use hickory_server::server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo};

use crate::authority::edns::lookup_options_for_edns;
use crate::error::HickoryError;
use crate::rr::Name;

/// Error type for catalog operations
///
/// This error type wraps any error that can occur during catalog operations
/// such as zone storage, retrieval, or DNS processing.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct CatalogError(Box<dyn std::error::Error + Send + Sync>);

impl CatalogError {
    /// Create a new catalog error from any error type
    ///
    /// Wraps the provided error in a CatalogError for consistent error handling
    /// throughout the catalog system.
    ///
    /// # Arguments
    ///
    /// * `error` - The error to wrap
    ///
    /// # Returns
    ///
    /// A new CatalogError instance
    pub(crate) fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        CatalogError(error.into())
    }
}

/// Trait for storing and retrieving DNS zones
///
/// This trait defines the interface for a zone storage backend that can persist
/// and retrieve DNS zones. Implementations might use databases, files, or other
/// storage mechanisms.
#[async_trait::async_trait]
pub trait CatalogStore<A> {
    /// Find zones by origin name
    ///
    /// Searches for zones that match the given origin name. This is used during
    /// DNS query processing to locate the appropriate authority for a request.
    ///
    /// # Arguments
    ///
    /// * `origin` - The origin name to search for
    ///
    /// # Returns
    ///
    /// A vector of zones matching the origin, or None if no matches are found
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails
    async fn find(&self, origin: &LowerName) -> Result<Option<Vec<A>>, CatalogError>;

    /// Insert or update zones for a given name
    ///
    /// Stores zones in the catalog, replacing any existing zones with the same name.
    /// This is used when zones are loaded or updated.
    ///
    /// # Arguments
    ///
    /// * `name` - The zone name
    /// * `zones` - The zones to store
    ///
    /// # Returns
    ///
    /// Success or an error if the operation fails
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails
    async fn upsert(&self, name: LowerName, zones: &[A]) -> Result<(), CatalogError>;

    /// List all zone names in the catalog
    ///
    /// Returns a list of all zone names currently stored in the catalog.
    /// This is useful for administrative operations and zone management.
    ///
    /// # Returns
    ///
    /// A vector of all zone names
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails
    async fn list(&self, origin: &LowerName) -> Result<Vec<Name>, CatalogError>;

    /// Remove a zone from the catalog
    ///
    /// Removes all zones with the given name from the catalog.
    ///
    /// # Arguments
    ///
    /// * `name` - The zone name to remove
    ///
    /// # Returns
    ///
    /// The removed zones, or None if no zones were found
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails
    async fn remove(&self, name: &LowerName) -> Result<Option<Vec<A>>, CatalogError>;
}

/// DNS Zone Catalog
///
/// A catalog manages a collection of DNS zones and provides the main interface
/// for DNS query processing. It acts as a dispatcher that routes DNS requests
/// to the appropriate zone authorities.
///
/// The catalog supports:
/// - Zone storage and retrieval
/// - DNS query processing
/// - DNS UPDATE operations
/// - EDNS handling
/// - Multiple zone authorities per name
pub struct Catalog<A> {
    zones: Arc<dyn CatalogStore<A> + Send + Sync + 'static>,
}

impl<A> fmt::Debug for Catalog<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Catalog").finish()
    }
}

impl<A> Clone for Catalog<A> {
    fn clone(&self) -> Self {
        Self {
            zones: self.zones.clone(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument("send", skip_all, level = "trace")]
async fn lookup_response(
    response: LookupControlFlow<Box<dyn LookupObject>>,
    response_edns: Option<Edns>,
    request: &Request,
    authority: &dyn AuthorityObject,
    request_id: u16,
    query: &LowerQuery,
    edns: Option<&Edns>,
) -> Result<Message, LookupError> {
    tracing::trace!("sending lookup response");
    // We no longer need the context from LookupControlFlow, so decompose into a standard Result
    // to clean up the rest of the match conditions
    let Some(result) = response.map_result() else {
        tracing::error!("impossible skip detected after final lookup result");
        return Err(LookupError::ResponseCode(ResponseCode::ServFail));
    };

    let (response_header, sections) =
        build_response(result, authority, request_id, request.header(), query, edns).await;

    let mut message = Message::new();
    message.set_header(response_header);
    message.add_queries(request.queries().iter().map(|q| q.original().clone()));
    message.add_answers(sections.answers.iter().cloned());
    message.add_name_servers(sections.ns.iter().cloned());
    message.add_name_servers(sections.soa.iter().cloned());
    message.add_additionals(sections.additionals.iter().cloned());

    if let Some(resp_edns) = response_edns {
        message.set_edns(resp_edns);
    }

    Ok(message)
}

struct LookupSections {
    answers: Box<dyn LookupObject>,
    ns: Box<dyn LookupObject>,
    soa: Box<dyn LookupObject>,
    additionals: Box<dyn LookupObject>,
}

async fn build_response(
    result: Result<Box<dyn LookupObject>, LookupError>,
    authority: &dyn AuthorityObject,
    _request_id: u16,
    request_header: &Header,
    query: &LowerQuery,
    edns: Option<&Edns>,
) -> (Header, LookupSections) {
    let lookup_options = lookup_options_for_edns(edns);

    let mut response_header = Header::response_from_request(request_header);
    response_header.set_authoritative(authority.zone_type().is_authoritative());

    if authority.zone_type().is_authoritative() {
        let answers = match result {
            Ok(records) => {
                tracing::trace!("authoritative lookup successful");
                response_header.set_response_code(ResponseCode::NoError);
                response_header.set_authoritative(true);
                Some(records)
            }
            // This request was refused
            // TODO: there are probably other error cases that should just drop through (FormErr, ServFail)
            Err(LookupError::ResponseCode(ResponseCode::Refused)) => {
                tracing::trace!("refusing lookup");
                response_header.set_response_code(ResponseCode::Refused);
                return (
                    response_header,
                    LookupSections {
                        answers: Box::<AuthLookup>::default(),
                        ns: Box::<AuthLookup>::default(),
                        soa: Box::<AuthLookup>::default(),
                        additionals: Box::<AuthLookup>::default(),
                    },
                );
            }
            Err(e) => {
                if e.is_nx_domain() {
                    tracing::trace!("NXDomain error");
                    response_header.set_response_code(ResponseCode::NXDomain);
                } else if e.is_name_exists() {
                    tracing::trace!("NameExists error");
                    response_header.set_response_code(ResponseCode::NoError);
                };
                None
            }
        };

        tracing::trace!("process ns and soa");
        let (ns, soa) = if answers.is_some() {
            // SOA queries should return the NS records as well.
            if query.query_type().is_soa() {
                // This was a successful authoritative lookup for SOA:
                //   get the NS records as well.
                tracing::trace!("ns lookup");
                match authority.ns(lookup_options).await.map_result() {
                    Some(Ok(ns)) => (Some(ns), None),
                    Some(Err(e)) => {
                        tracing::warn!("ns_lookup errored: {e}");
                        (None, None)
                    }
                    None => {
                        tracing::warn!("ns_lookup unexpected skip");
                        (None, None)
                    }
                }
            } else {
                tracing::trace!("query is not soa, skipping process");
                //TODO: Add DNSSEC support here
                (None, None)
            }
        } else {
            tracing::trace!("no answers to process");
            let nsecs = None;
            match authority.soa_secure(lookup_options).await.map_result() {
                Some(Ok(soa)) => (nsecs, Some(soa)),
                Some(Err(e)) => {
                    tracing::warn!("failed to lookup soa: {e}");
                    (nsecs, None)
                }
                None => {
                    tracing::warn!("unexpected lookup skip");
                    (None, None)
                }
            }
        };

        tracing::trace!("assemble response");
        // everything is done, return results.
        let (answers, additionals) = match answers {
            Some(mut answers) => match answers.take_additionals() {
                Some(additionals) => (answers, additionals),
                None => (
                    answers,
                    Box::<AuthLookup>::default() as Box<dyn LookupObject>,
                ),
            },
            None => (
                Box::<AuthLookup>::default() as Box<dyn LookupObject>,
                Box::<AuthLookup>::default() as Box<dyn LookupObject>,
            ),
        };

        let sections = LookupSections {
            answers,
            ns: ns.unwrap_or_else(|| Box::<AuthLookup>::default()),
            soa: soa.unwrap_or_else(|| Box::<AuthLookup>::default()),
            additionals,
        };
        (response_header, sections)
    } else {
        tracing::trace!("process non-authorative response");
        response_header.set_recursion_available(true);

        enum Answer {
            Normal(Box<dyn LookupObject>),
            NoRecords(Box<AuthLookup>),
        }

        let (answers, authorities) = match result {
            Ok(_) | Err(_) if !request_header.recursion_desired() => {
                tracing::info!(
                    id = request_header.id(),
                    "request disabled recursion, returning REFUSED"
                );
                response_header.set_response_code(ResponseCode::Refused);

                return (
                    response_header,
                    LookupSections {
                        answers: Box::new(EmptyLookup),
                        ns: Box::new(EmptyLookup),
                        soa: Box::new(EmptyLookup),
                        additionals: Box::new(EmptyLookup),
                    },
                );
            }
            Ok(l) => (Answer::Normal(l), Box::<AuthLookup>::default()),
            Err(e) if e.is_no_records_found() || e.is_nx_domain() => {
                tracing::debug!(error = ?e, "error resolving");

                if e.is_nx_domain() {
                    response_header.set_response_code(ResponseCode::NXDomain);
                }

                // Collect all of the authority records, except the SOA
                let authorities = if let Some(authorities) = e.authorities() {
                    let authorities = authorities
                        .iter()
                        .filter_map(|x| {
                            // if we have another record (probably a dnssec record) that
                            // matches the query name, but wasn't included in the answers
                            // section, change the NXDomain response to NoError
                            if *x.name() == **query.name() {
                                tracing::debug!(
                                    query_name = %query.name(),
                                    record = ?x,
                                    "changing response code from NXDomain to NoError due to other record",
                                );
                                response_header.set_response_code(ResponseCode::NoError);
                            }

                            match x.record_type() {
                                RecordType::SOA => None,
                                _ => Some(Arc::new(RecordSet::from(x.clone()))),
                            }
                        })
                        .collect();

                    Box::new(AuthLookup::answers(
                        LookupRecords::many(LookupOptions::default(), authorities),
                        None,
                    ))
                } else {
                    Box::<AuthLookup>::default()
                };

                if let Some(soa) = e.into_soa() {
                    let soa = soa.into_record_of_rdata();
                    let record_set = Arc::new(RecordSet::from(soa));
                    let records = LookupRecords::new(LookupOptions::default(), record_set);

                    (
                        Answer::NoRecords(Box::new(AuthLookup::SOA(records))),
                        authorities,
                    )
                } else {
                    (Answer::Normal(Box::new(EmptyLookup)), authorities)
                }
            }
            Err(e) => {
                response_header.set_response_code(ResponseCode::ServFail);
                tracing::debug!(error = ?e, "error resolving");
                (
                    Answer::Normal(Box::new(EmptyLookup)),
                    Box::<AuthLookup>::default(),
                )
            }
        };

        //TODO: Validate DNSSEC here

        // Strip out DNSSEC records unless the DO bit is set.
        let authorities = if !lookup_options.dnssec_ok() {
            let auth = authorities
                .into_iter()
                .filter_map(|rrset| {
                    let record_type = rrset.record_type();
                    if record_type == query.query_type() || !record_type.is_dnssec() {
                        Some(Arc::new(RecordSet::from(rrset.clone())))
                    } else {
                        None
                    }
                })
                .collect();

            Box::new(AuthLookup::answers(
                LookupRecords::many(LookupOptions::default(), auth),
                None,
            ))
        } else {
            authorities
        };

        let sections = match answers {
            Answer::Normal(answers) => LookupSections {
                answers,
                ns: authorities,
                soa: Box::<AuthLookup>::default(),
                additionals: Box::<AuthLookup>::default(),
            },
            Answer::NoRecords(soa) => LookupSections {
                answers: Box::new(EmptyLookup),
                ns: authorities,
                soa,
                additionals: Box::<AuthLookup>::default(),
            },
        };

        (response_header, sections)
    }
}

async fn lookup(
    request_info: RequestInfo<'_>,
    authorities: &[&dyn AuthorityObject],
    request: &Request,
    response_edns: Option<Edns>,
) -> Result<Message, LookupError> {
    let edns = request.edns();
    let lookup_options = lookup_options_for_edns(edns);
    let request_id = request.id();

    // log algorithms being requested
    if lookup_options.dnssec_ok() {
        tracing::info!("request: {request_id} lookup_options: {lookup_options:?}");
    }

    let query = request_info.query;

    for (authority_index, authority) in authorities.iter().enumerate() {
        tracing::debug!(
            origin = %authority.origin(),
            qtype = %query.query_type(),
            name = %query.name(),
            "querying"
        );

        let mut result = authority.search(request_info.clone(), lookup_options).await;

        if let LookupControlFlow::Skip = result {
            tracing::trace!("authority {} skipped", authority.origin());
            continue;
        } else if result.is_continue() {
            tracing::trace!(
                "authority {} did handle request with continue",
                authority.origin()
            );

            // For LookupControlFlow::Continue results, we'll call consult on every
            // authority, except the authority that returned the Continue result.
            for (continue_index, consult_authority) in authorities.iter().enumerate() {
                if continue_index == authority_index {
                    tracing::trace!("skipping current authority consult (index {continue_index})");
                    continue;
                } else {
                    tracing::trace!("calling authority consult (index {continue_index})");
                }

                result = consult_authority
                    .consult(
                        request_info.query.name(),
                        request_info.query.query_type(),
                        lookup_options_for_edns(response_edns.as_ref()),
                        result,
                    )
                    .await
            }
        } else {
            tracing::trace!(
                "authority {} did handle request with break",
                authority.origin()
            );
        }

        tracing::trace!("build {result}");
        return lookup_response(
            result,
            response_edns,
            request,
            &**authority,
            request_id,
            query,
            edns,
        )
        .await;
    }

    tracing::error!("end of chained authority loop reached with all authorities not answering");
    Err(LookupError::ResponseCode(ResponseCode::ServFail))
}

impl<A> Catalog<A> {
    /// Create a new catalog with the specified zone store
    ///
    /// Creates a new catalog instance that uses the provided zone store
    /// for persisting and retrieving DNS zones.
    ///
    /// # Arguments
    ///
    /// * `zones` - The zone store implementation to use
    ///
    /// # Returns
    ///
    /// A new catalog instance
    pub fn new<T>(zones: T) -> Self
    where
        T: CatalogStore<A> + Send + Sync + 'static,
    {
        Self {
            zones: Arc::new(zones),
        }
    }

    /// Insert or update zones for a given name
    ///
    /// Stores zones in the catalog, replacing any existing zones with the same name.
    /// This is the primary method for adding zones to the catalog.
    ///
    /// # Arguments
    ///
    /// * `name` - The zone name
    /// * `zones` - The zones to store
    ///
    /// # Returns
    ///
    /// Success or an error if the operation fails
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage fails
    pub async fn upsert(&self, name: LowerName, zones: Vec<A>) -> Result<(), CatalogError> {
        (*self.zones).upsert(name, &zones).await
    }

    /// Remove a zone from the catalog
    ///
    /// Removes all zones with the given name from the catalog.
    ///
    /// # Arguments
    ///
    /// * `name` - The zone name to remove
    ///
    /// # Returns
    ///
    /// The removed zones, or None if no zones were found
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage fails
    pub async fn remove(&self, name: &LowerName) -> Result<Option<Vec<A>>, CatalogError> {
        (*self.zones).remove(name).await
    }

    /// Find zones by name
    ///
    /// Searches for zones that match the given name. This is used internally
    /// during DNS query processing to locate the appropriate authority.
    ///
    /// # Arguments
    ///
    /// * `name` - The zone name to search for
    ///
    /// # Returns
    ///
    /// A vector of zones matching the name, or None if no matches are found
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage fails
    pub async fn find(&self, name: &LowerName) -> Result<Option<Vec<A>>, CatalogError> {
        tracing::debug!("searching for {}", name);
        (*self.zones).find(name).await
    }

    /// Lists zones that match the given name. This is used internally
    /// during DNS query processing to locate the appropriate authority.
    ///
    /// # Arguments
    ///
    /// * `name` - The zone name to search for
    ///
    /// # Returns
    ///
    /// A vector of zones matching the name, or None if no matches are found
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage fails
    pub async fn list(&self, name: &LowerName) -> Result<Vec<Name>, CatalogError> {
        (*self.zones).list(name).await
    }
}

impl<A> Catalog<A>
where
    A: AsRef<dyn AuthorityObject>,
{
    /// Process a DNS lookup request
    ///
    /// Handles DNS queries by finding the appropriate zone authority and
    /// delegating the lookup to that authority. This is the main entry point
    /// for DNS query processing.
    ///
    /// # Arguments
    ///
    /// * `request` - The DNS request to process
    /// * `edns` - Optional EDNS information from the request
    /// * `response_handle` - Handler for sending the response
    ///
    /// # Returns
    ///
    /// Information about the response that was sent
    #[tracing::instrument(skip_all, level = "trace")]
    pub async fn lookup(
        &self,
        request: &Request,
        edns: Option<Edns>,
    ) -> Result<Message, HickoryError> {
        let Ok(request_info) = request.request_info() else {
            tracing::trace!("Invalid request format");
            return Ok(Message::error_msg(
                request.id(),
                request.op_code(),
                ResponseCode::FormErr,
            ));
        };

        let authorities: Vec<A> = match self.find(request_info.query.name()).await {
            Ok(Some(zones)) => zones,
            Ok(None) => {
                tracing::trace!("No authorities found for {}", request_info.query.name());
                return Ok(Message::error_msg(
                    request.id(),
                    request.op_code(),
                    ResponseCode::Refused,
                ));
            }
            Err(error) => {
                tracing::error!("Internal Error finding zones: {error}");
                return Ok(Message::error_msg(
                    request.id(),
                    request.op_code(),
                    ResponseCode::ServFail,
                ));
            }
        };

        tracing::trace!("{} authorities found", authorities.len());

        let refs = authorities.iter().map(|za| za.as_ref()).collect::<Vec<_>>();

        match lookup(
            request_info.clone(),
            &refs,
            request,
            edns.as_ref().map(|arc| Borrow::<Edns>::borrow(arc).clone()),
        )
        .await
        {
            Ok(message) => Ok(message),
            Err(LookupError::ResponseCode(code)) => {
                Ok(Message::error_msg(request.id(), request.op_code(), code))
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl<A> Catalog<A>
where
    A: AsRef<dyn AuthorityObject>,
{
    /// Insert a single zone into the catalog
    ///
    /// Convenience method for inserting a single zone authority into the catalog.
    /// The zone name is automatically derived from the zone's origin.
    ///
    /// # Arguments
    ///
    /// * `zone` - The zone authority to insert
    ///
    /// # Returns
    ///
    /// Success or an error if the operation fails
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage fails
    pub async fn insert(&self, zone: A) -> Result<(), CatalogError> {
        let name = LowerName::new(zone.as_ref().origin());
        (*self.zones).upsert(name, &[zone]).await
    }

    async fn update(&self, request: &Request, edns: Option<Edns>) -> Result<Message, HickoryError> {
        let request_info = match request.request_info() {
            Ok(request_info) => request_info,
            Err(error) => {
                tracing::warn!("Update Request Protocol Error: {error}");
                return Ok(Message::error_msg(
                    request.id(),
                    request.op_code(),
                    ResponseCode::ServFail,
                ));
            }
        };
        if request_info.query.query_type() != RecordType::SOA {
            return Ok(Message::error_msg(
                request.id(),
                request.op_code(),
                ResponseCode::ServFail,
            ));
        }

        let authorities = match self.find(request_info.query.name()).await {
            Ok(Some(zones)) => zones,
            Ok(None) => {
                return Ok(Message::error_msg(
                    request.id(),
                    request.op_code(),
                    ResponseCode::NotAuth,
                ));
            }
            Err(error) => {
                tracing::error!("Error finding zones: {error}");
                return Ok(Message::error_msg(
                    request.id(),
                    request.op_code(),
                    ResponseCode::ServFail,
                ));
            }
        };

        if let Some(authority) = authorities.into_iter().next() {
            let update_result = AuthorityObject::update(authority.as_ref(), request).await;
            let response_code = match update_result {
                // successful update
                Ok(..) => ResponseCode::NoError,
                Err(response_code) => response_code,
            };

            let mut response = Message::new();
            response.add_queries(request.queries().iter().map(|lq| lq.original().clone()));
            response
                .set_id(request.id())
                .set_op_code(OpCode::Update)
                .set_message_type(MessageType::Response)
                .set_response_code(response_code);
            if let Some(edns) = edns {
                response.set_edns(edns);
            }

            return Ok(response);
        }

        Ok(Message::error_msg(
            request.id(),
            request.op_code(),
            ResponseCode::ServFail,
        ))
    }

    async fn handle_edns(&self, request: &Request) -> Result<Option<Edns>, Message> {
        if let Some(req_edns) = request.edns() {
            let mut response = Message::new();
            response.add_queries(request.queries().iter().map(|lq| lq.original().clone()));
            let mut response_header = Header::response_from_request(request.header());

            let mut resp_edns: Edns = Edns::new();

            // check our version against the request
            // TODO: what version are we?
            let our_version = 0;
            resp_edns.set_dnssec_ok(true);
            resp_edns.set_max_payload(req_edns.max_payload().max(512));
            resp_edns.set_version(our_version);

            if req_edns.version() > our_version {
                tracing::warn!(
                    "request edns version greater than {}: {}",
                    our_version,
                    req_edns.version()
                );
                response_header.set_response_code(ResponseCode::BADVERS);
                resp_edns.set_rcode_high(ResponseCode::BADVERS.high());
                response.set_edns(resp_edns);
                response.set_header(response_header);

                return Err(response);
            }
            Ok(Some(resp_edns))
        } else {
            Ok(None)
        }
    }

    #[tracing::instrument(skip_all, fields(op=%request.op_code(), id=%request.id()), level="debug")]
    async fn handle_query(
        &self,
        request: &Request,
        edns: Option<Edns>,
    ) -> Result<Message, HickoryError> {
        match request.op_code() {
            OpCode::Query => self.lookup(request, edns).await,
            OpCode::Update => self.update(request, edns).await,
            c => {
                tracing::warn!("Unimplemented op code: {c}");
                Ok(Message::error_msg(request.id(), c, ResponseCode::NotImp))
            }
        }
    }

    async fn respond_error_code<R: ResponseHandler>(
        &self,
        response_handle: &mut R,
        request: &Request,
        response_code: ResponseCode,
    ) -> ResponseInfo {
        let mut header = Header::new();
        header.set_response_code(response_code);
        self.respond(
            response_handle,
            MessageResponseBuilder::from_message_request(request)
                .error_msg(request.header(), response_code),
        )
        .await
    }

    async fn respond<'q, 'a, R: ResponseHandler>(
        &self,
        response_handle: &mut R,
        message: MessageResponse<
            'q,
            'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send,
        >,
    ) -> ResponseInfo {
        return match response_handle.send_response(message).await {
            Ok(info) => info,
            Err(error) => {
                tracing::error!("Send error: {error}");
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        };
    }
}

impl<A> tower::Service<Request> for Catalog<A>
where
    A: AsRef<dyn AuthorityObject> + Send + 'static,
{
    type Response = Message;

    type Error = HickoryError;

    type Future = self::future::CatalogFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        tracing::trace!("request {}", request.message_type());

        let catalog = self.clone();

        self::future::CatalogFuture::new(async move {
            let edns = match catalog.handle_edns(&request).await {
                Ok(edns) => edns,
                Err(message) => return Ok(message),
            };

            match request.message_type() {
                MessageType::Query => catalog.handle_query(&request, edns).await,
                MessageType::Response => {
                    tracing::warn!("got a response as a request from id: {}", request.id());
                    Err(HickoryError::ResponseAsRequest)
                }
            }
        })
    }
}

#[async_trait::async_trait]
impl<A> RequestHandler for Catalog<A>
where
    A: AsRef<dyn AuthorityObject> + Send + 'static,
{
    async fn handle_request<R>(&self, request: &Request, mut response_handle: R) -> ResponseInfo
    where
        R: ResponseHandler,
    {
        let edns = match self.handle_edns(request).await {
            Ok(edns) => edns,
            Err(message) => {
                return self
                    .respond(
                        &mut response_handle,
                        MessageResponseBuilder::from_message_request(request)
                            .build_no_records(*message.header()),
                    )
                    .await;
            }
        };

        let msg = match request.message_type() {
            MessageType::Query => self.handle_query(request, edns).await,
            MessageType::Response => {
                tracing::warn!("got a response as a request from id: {}", request.id());
                return self
                    .respond_error_code(&mut response_handle, request, ResponseCode::FormErr)
                    .await;
            }
        };

        match msg {
            Ok(message) => {
                let rmsg = MessageResponseBuilder::from_message_request(request);
                let ns = message.name_servers();
                let first_soa = ns
                    .iter()
                    .position(|rr| rr.record_type() == RecordType::SOA)
                    .unwrap_or(ns.len());

                let (ns_only, soa_only) = ns.split_at(first_soa);

                let msg = rmsg.build(
                    *message.header(),
                    message.answers().iter(),
                    ns_only.iter(),
                    soa_only.iter(),
                    message.additionals().iter(),
                );

                self.respond(&mut response_handle, msg).await
            }
            Err(error) => {
                tracing::error!("Error handling request: {error}");
                self.respond_error_code(&mut response_handle, request, ResponseCode::ServFail)
                    .await
            }
        }
    }
}

mod future {
    use std::{
        fmt,
        pin::Pin,
        task::{Context, Poll},
    };

    use hickory_proto::op::Message;

    use crate::error::HickoryError;

    pub struct CatalogFuture {
        inner: Pin<Box<dyn Future<Output = Result<Message, HickoryError>> + Send + 'static>>,
    }

    impl fmt::Debug for CatalogFuture {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CatalogFuture").finish()
        }
    }

    impl CatalogFuture {
        pub(super) fn new<F>(future: F) -> Self
        where
            F: Future<Output = Result<Message, HickoryError>> + Send + 'static,
        {
            Self {
                inner: Box::pin(future),
            }
        }
    }

    impl Future for CatalogFuture {
        type Output = Result<Message, HickoryError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.inner.as_mut().poll(cx)
        }
    }
}
