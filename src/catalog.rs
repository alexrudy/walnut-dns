//! Hickory-dns Catalog integration
use std::{borrow::Borrow, sync::Arc};

use hickory_proto::op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{LowerName, RecordSet, RecordType};
use hickory_server::authority::{
    AuthLookup, AuthorityObject, EmptyLookup, LookupControlFlow, LookupError, LookupObject,
    LookupOptions, LookupRecords, MessageResponseBuilder,
};
use hickory_server::server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo};

use crate::authority::edns::EdnsResponse;
use crate::authority::edns::lookup_options_for_edns;
use crate::authority::response::{ResponseHandleExt, ResponseInfoExt, ResponseResultExt};
use crate::rr::Name;

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct CatalogError(Box<dyn std::error::Error + Send + Sync>);

impl CatalogError {
    pub(crate) fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        CatalogError(error.into())
    }
}

pub trait CatalogStore<A> {
    fn find(&self, origin: &LowerName) -> Result<Option<Vec<A>>, CatalogError>;
    fn upsert(&self, name: LowerName, zones: &[A]) -> Result<(), CatalogError>;
    fn list(&self) -> Result<Vec<Name>, CatalogError>;
    fn remove(&self, name: &LowerName) -> Result<Option<Vec<A>>, CatalogError>;
}

pub struct Catalog<A> {
    zones: Arc<dyn CatalogStore<A> + Send + Sync + 'static>,
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument("send", skip_all, level = "trace")]
async fn send_lookup_response<R: ResponseHandler>(
    response_handle: &mut R,
    response: LookupControlFlow<Box<dyn LookupObject>>,
    response_edns: Option<Edns>,
    request: &Request,
    authority: &dyn AuthorityObject,
    request_id: u16,
    query: &LowerQuery,
    edns: Option<&Edns>,
) -> Result<ResponseInfo, LookupError> {
    tracing::trace!("sending lookup response");
    // We no longer need the context from LookupControlFlow, so decompose into a standard Result
    // to clean up the rest of the match conditions
    let Some(result) = response.map_result() else {
        tracing::error!("impossible skip detected after final lookup result");
        return Err(LookupError::ResponseCode(ResponseCode::ServFail));
    };

    let (response_header, sections) =
        build_response(result, authority, request_id, request.header(), query, edns).await;

    let mut message_response = MessageResponseBuilder::from_message_request(request).build(
        response_header,
        sections.answers.iter(),
        sections.ns.iter(),
        sections.soa.iter(),
        sections.additionals.iter(),
    );

    if let Some(resp_edns) = response_edns {
        message_response.set_edns(resp_edns);
    }

    match response_handle.send_response(message_response).await {
        Err(e) => {
            tracing::error!("error sending response: {e}");
            return Err(LookupError::Io(e));
        }
        Ok(l) => return Ok(l),
    }
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

async fn lookup<R: ResponseHandler + Unpin>(
    request_info: RequestInfo<'_>,
    authorities: &[&dyn AuthorityObject],
    request: &Request,
    response_edns: Option<Edns>,
    mut response_handle: R,
) -> Result<ResponseInfo, LookupError> {
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
            "performing {query:?} query on authority {origin} with request id {request_id}",
            origin = authority.origin(),
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

        tracing::trace!("SEND {result}");
        return send_lookup_response(
            &mut response_handle,
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
    pub fn new<T>(zones: T) -> Self
    where
        T: CatalogStore<A> + Send + Sync + 'static,
    {
        Self {
            zones: Arc::new(zones),
        }
    }

    pub fn upsert(&self, name: LowerName, zones: Vec<A>) -> Result<(), CatalogError> {
        (*self.zones).upsert(name, &zones)
    }

    pub fn remove(&self, name: &LowerName) -> Result<Option<Vec<A>>, CatalogError> {
        (*self.zones).remove(name)
    }

    fn find(&self, name: &LowerName) -> Result<Option<Vec<A>>, CatalogError> {
        tracing::debug!("searching for {}", name);
        (*self.zones).find(&name)
    }
}

impl<A> Catalog<A>
where
    A: AsRef<dyn AuthorityObject>,
{
    #[tracing::instrument(skip_all, level = "trace")]
    pub async fn lookup<R: ResponseHandler>(
        &self,
        request: &Request,
        edns: Option<Edns>,
        response_handle: &mut R,
    ) -> ResponseInfo {
        let Ok(request_info) = request.request_info() else {
            tracing::trace!("Invalid request format");
            return response_handle
                .send_error(request, ResponseCode::FormErr)
                .await;
        };

        let authorities: Vec<A> = match self.find(request_info.query.name()) {
            Ok(Some(zones)) => zones,
            Ok(None) => {
                tracing::trace!("No authorities found for {}", request_info.query.name());
                return response_handle
                    .send_error(request, ResponseCode::Refused)
                    .await;
            }
            Err(error) => {
                tracing::error!("Internal Error finding zones: {error}");
                return response_handle
                    .send_error(request, ResponseCode::ServFail)
                    .await;
            }
        };

        tracing::trace!("{} authorities found", authorities.len());

        let refs = authorities.iter().map(|za| za.as_ref()).collect::<Vec<_>>();

        match lookup(
            request_info.clone(),
            &refs,
            request,
            edns.as_ref().map(|arc| Borrow::<Edns>::borrow(arc).clone()),
            response_handle.clone(),
        )
        .await
        {
            Ok(lookup) => lookup,
            Err(_) => ResponseInfo::code_serve_failed(),
        }
    }
}

impl<A> Catalog<A>
where
    A: AsRef<dyn AuthorityObject>,
{
    pub fn insert(&self, zone: A) -> Result<(), CatalogError> {
        let name = LowerName::new(zone.as_ref().origin());
        (*self.zones).upsert(name, &vec![zone])
    }

    async fn update<R: ResponseHandler>(
        &self,
        request: &Request,
        edns: Option<Edns>,
        response_handle: &mut R,
    ) -> ResponseInfo {
        let request_info = match request.request_info() {
            Ok(request_info) => request_info,
            Err(error) => {
                tracing::warn!("Update Request Protocol Error: {error}");
                return response_handle
                    .send_error(request, ResponseCode::ServFail)
                    .await;
            }
        };
        if request_info.query.query_type() != RecordType::SOA {
            return response_handle
                .send_error(request, ResponseCode::ServFail)
                .await;
        }

        let authorities = match self.find(request_info.query.name()) {
            Ok(Some(zones)) => zones,
            Ok(None) => {
                return response_handle
                    .send_error(request, ResponseCode::NotAuth)
                    .await;
            }
            Err(error) => {
                tracing::error!("Error finding zones: {error}");
                return response_handle
                    .send_error(request, ResponseCode::ServFail)
                    .await;
            }
        };

        for authority in authorities {
            let update_result = AuthorityObject::update(authority.as_ref(), request).await;
            let response_code = match update_result {
                // successful update
                Ok(..) => ResponseCode::NoError,
                Err(response_code) => response_code,
            };

            let mut response = MessageResponseBuilder::from_message_request(request);
            let mut response_header = Header::default();
            response_header.set_id(request.id());
            response_header.set_op_code(OpCode::Update);
            response_header.set_message_type(MessageType::Response);
            response_header.set_response_code(response_code);

            if let Some(edns) = edns {
                response.edns(edns);
            }

            return response_handle
                .send_response(response.build_no_records(response_header))
                .await
                .into_info();
        }

        response_handle
            .send_error(request, ResponseCode::ServFail)
            .await
    }

    async fn handle_edns<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
    ) -> EdnsResponse {
        if let Some(req_edns) = request.edns() {
            let mut response = MessageResponseBuilder::from_message_request(request);
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
                response.edns(resp_edns);

                return EdnsResponse::Sent(
                    response_handle
                        .send_response(response.build_no_records(response_header))
                        .await
                        .into_info(),
                );
            }

            EdnsResponse::Response(resp_edns)
        } else {
            EdnsResponse::None
        }
    }

    #[tracing::instrument(skip_all, fields(op=%request.op_code(), id=%request.id()), level="debug")]
    async fn handle_query<R: ResponseHandler>(
        &self,
        request: &Request,
        edns: Option<Edns>,
        response_handle: &mut R,
    ) -> ResponseInfo {
        match request.op_code() {
            OpCode::Query => self.lookup(request, edns, response_handle).await,
            OpCode::Update => self.update(request, edns, response_handle).await,
            c => {
                tracing::warn!("Unimplemented op code: {c}");
                response_handle
                    .send_error(request, ResponseCode::NotImp)
                    .await
            }
        }
    }
}

#[async_trait::async_trait]
impl<A> RequestHandler for Catalog<A>
where
    A: AsRef<dyn AuthorityObject> + Send + 'static,
{
    #[tracing::instrument("dns", skip_all, fields(id=%request.id()), level="debug")]
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        tracing::trace!("request {}", request.message_type());

        let edns = match self.handle_edns(request, &mut response_handle).await {
            EdnsResponse::Response(edns) => Some(edns),
            EdnsResponse::None => None,
            EdnsResponse::Sent(response_info) => return response_info,
        };

        match request.message_type() {
            MessageType::Query => self.handle_query(request, edns, &mut response_handle).await,
            MessageType::Response => {
                tracing::warn!("got a response as a request from id: {}", request.id());
                response_handle
                    .send_error(request, ResponseCode::FormErr)
                    .await
            }
        }
    }
}
