use core::fmt;
use std::sync::Arc;

use hickory_proto::rr::{Name, RecordType};

use crate::rr::{Record, RecordSet, RecordSetIter};

use super::LookupError;

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct LookupOptions {
    /// Whether to enable DNSSEC validation.
    pub dnssec_ok: bool,
}

impl LookupOptions {
    pub fn for_dnssec(dnssec_ok: bool) -> Self {
        Self { dnssec_ok }
    }

    pub fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }
}

/// The result of a DNS lookup, containing the matched records and any additional data.
#[derive(Debug, Clone)]
pub struct LookupRecords {
    options: LookupOptions,
    kind: LookupKind,
}

impl Default for LookupRecords {
    fn default() -> Self {
        Self::empty()
    }
}

impl LookupRecords {
    pub fn empty() -> Self {
        Self {
            options: LookupOptions::default(),
            kind: LookupKind::Empty,
        }
    }

    pub fn records(answers: Vec<Arc<RecordSet>>, options: LookupOptions) -> Self {
        Self {
            options,
            kind: LookupKind::Records {
                answers,
                additionals: None,
            },
        }
    }

    pub fn answers(
        answers: Vec<Arc<RecordSet>>,
        additionals: Vec<Arc<RecordSet>>,
        options: LookupOptions,
    ) -> Self {
        Self {
            options,
            kind: LookupKind::Records {
                answers,
                additionals: Some(additionals),
            },
        }
    }

    pub fn set_additionals(&mut self, additional: Vec<Arc<RecordSet>>) {
        if let LookupKind::Records { additionals, .. } = &mut self.kind {
            *additionals = Some(additional);
        }
    }

    pub fn soa(soa: Arc<RecordSet>, options: LookupOptions) -> Self {
        Self {
            options,
            kind: LookupKind::SOA(soa),
        }
    }

    pub fn axfr(soa: Arc<RecordSet>, records: Vec<Arc<RecordSet>>, options: LookupOptions) -> Self {
        Self {
            options,
            kind: LookupKind::AXFR { soa, records },
        }
    }

    pub fn any(rrsets: Vec<Arc<RecordSet>>, query_name: Name, options: LookupOptions) -> Self {
        Self {
            options,
            kind: LookupKind::ANY { rrsets, query_name },
        }
    }

    pub fn lookup_options(&self) -> &LookupOptions {
        &self.options
    }

    pub fn len(&self) -> usize {
        match &self.kind {
            LookupKind::Empty => 0,
            LookupKind::Records {
                answers,
                additionals,
            } => {
                answers.iter().map(|rrset| rrset.len()).sum::<usize>()
                    + additionals
                        .as_ref()
                        .map_or(0, |a| a.iter().map(|rrset| rrset.len()).sum())
            }
            LookupKind::SOA(_) => 1,
            LookupKind::AXFR { .. } => self.iter().count(),
            LookupKind::ANY { .. } => self.iter().count(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn unwrap_record(&self) -> Option<Arc<RecordSet>> {
        match &self.kind {
            LookupKind::Empty => None,
            LookupKind::Records { answers, .. } => answers.first().cloned(),
            LookupKind::SOA(soa) => Some(soa.clone()),
            LookupKind::AXFR { soa, .. } => Some(soa.clone()),
            LookupKind::ANY { .. } => None,
        }
    }

    pub fn unwrap_records(&self) -> Option<Vec<Arc<RecordSet>>> {
        match &self.kind {
            LookupKind::Empty => None,
            LookupKind::Records { answers, .. } => Some(answers.clone()),
            LookupKind::SOA(_) => None,
            LookupKind::AXFR { records, .. } => Some(records.clone()),
            LookupKind::ANY { .. } => None,
        }
    }

    pub fn iter(&self) -> LookupRecordIter<'_> {
        self.into_iter()
    }

    pub fn take_additionals(&mut self) -> Option<Vec<Arc<RecordSet>>> {
        match &mut self.kind {
            LookupKind::Empty => None,
            LookupKind::Records { additionals, .. } => additionals.take(),
            LookupKind::SOA(_) => None,
            LookupKind::AXFR { .. } => None,
            LookupKind::ANY { .. } => None,
        }
    }
}

/// The kind of lookup result, indicating the type of data returned.
#[derive(Debug, Clone)]
enum LookupKind {
    Empty,
    Records {
        answers: Vec<Arc<RecordSet>>,
        additionals: Option<Vec<Arc<RecordSet>>>,
    },

    #[allow(clippy::upper_case_acronyms)]
    SOA(Arc<RecordSet>),

    #[allow(clippy::upper_case_acronyms)]
    AXFR {
        soa: Arc<RecordSet>,
        records: Vec<Arc<RecordSet>>,
    },

    #[allow(clippy::upper_case_acronyms)]
    ANY {
        rrsets: Vec<Arc<RecordSet>>,
        query_name: Name,
    },
}

impl<'r> IntoIterator for &'r LookupRecords {
    type Item = &'r Record;
    type IntoIter = LookupRecordIter<'r>;

    fn into_iter(self) -> Self::IntoIter {
        match &self.kind {
            LookupKind::Empty => LookupRecordIter {
                inner: LookupIter::Empty,
            },
            LookupKind::SOA(record) => LookupRecordIter {
                inner: LookupIter::Records(RrsetRecordsIter::new(vec![
                    record.records(self.options.dnssec_ok),
                ])),
            },
            LookupKind::Records {
                answers,
                additionals: _,
            } => LookupRecordIter {
                inner: LookupIter::Records(RrsetRecordsIter::new(
                    answers
                        .iter()
                        .rev()
                        .map(|rrset| rrset.records(self.options.dnssec_ok))
                        .collect(),
                )),
            },
            LookupKind::AXFR { soa, records } => LookupRecordIter {
                inner: LookupIter::AXFRRecords {
                    soa_start: Some(soa.records(self.options.dnssec_ok)),
                    records: RrsetRecordsIter::new(
                        records
                            .iter()
                            .rev()
                            .map(|rrset| rrset.records(self.options.dnssec_ok))
                            .collect(),
                    ),
                    soa_end: Some(soa.records(self.options.dnssec_ok)),
                },
            },
            LookupKind::ANY { rrsets, query_name } => LookupRecordIter {
                inner: LookupIter::AnyRecords {
                    records: RrsetRecordsIter::new(
                        rrsets
                            .iter()
                            .rev()
                            .map(|rrset| rrset.records(self.options.dnssec_ok))
                            .collect(),
                    ),
                    query_name: query_name.clone(),
                },
            },
        }
    }
}

pub struct RrsetRecordsIter<'r> {
    records: Vec<RecordSetIter<'r>>,
    current: Option<RecordSetIter<'r>>,
}

impl<'r> RrsetRecordsIter<'r> {
    pub fn new(records: Vec<RecordSetIter<'r>>) -> Self {
        Self {
            records,
            current: None,
        }
    }
}

impl<'r> Iterator for RrsetRecordsIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(record) = self.current.as_mut().and_then(Iterator::next) {
                return Some(record);
            }

            self.current = self.records.pop();
            self.current.as_ref()?;
        }
    }
}

enum LookupIter<'r> {
    Empty,
    Records(RrsetRecordsIter<'r>),
    AXFRRecords {
        soa_start: Option<RecordSetIter<'r>>,
        records: RrsetRecordsIter<'r>,
        soa_end: Option<RecordSetIter<'r>>,
    },
    AnyRecords {
        records: RrsetRecordsIter<'r>,
        query_name: Name,
    },
}

/// An iterator over the records in a lookup result.
pub struct LookupRecordIter<'r> {
    inner: LookupIter<'r>,
}

impl<'r> Iterator for LookupRecordIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            LookupIter::Empty => None,
            LookupIter::Records(records) => records.next(),
            LookupIter::AXFRRecords {
                soa_start,
                records,
                soa_end,
            } => loop {
                if let Some(soa) = soa_start.as_mut().and_then(Iterator::next) {
                    return Some(soa);
                }

                if let Some(record) = records.next() {
                    if record.record_type() == RecordType::SOA {
                        continue;
                    }
                    return Some(record);
                }

                if let Some(soa) = soa_end.as_mut().and_then(Iterator::next) {
                    return Some(soa);
                }

                return None;
            },
            LookupIter::AnyRecords {
                records,
                query_name,
            } => loop {
                if let Some(record) = records.next() {
                    if record.name() != query_name {
                        continue;
                    }
                    return Some(record);
                }

                return None;
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupControlFlow<T, E = LookupError> {
    Continue(Result<T, E>),
    Break(Result<T, E>),
    Skip,
}

impl<T, E> fmt::Display for LookupControlFlow<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupControlFlow::Continue(Ok(_)) => write!(f, "LookupControlFlow::Continue(Ok)"),
            LookupControlFlow::Continue(Err(_)) => write!(f, "LookupControlFlow::Continue(Err)"),
            LookupControlFlow::Break(Ok(_)) => write!(f, "LookupControlFlow::Break(Ok)"),
            LookupControlFlow::Break(Err(_)) => write!(f, "LookupControlFlow::Break(Err)"),
            LookupControlFlow::Skip => write!(f, "LookupControlFlow::Skip"),
        }
    }
}

impl<T, E> LookupControlFlow<T, E> {
    pub fn is_continue(&self) -> bool {
        matches!(self, LookupControlFlow::Continue(_))
    }
    pub fn is_break(&self) -> bool {
        matches!(self, LookupControlFlow::Break(_))
    }
    pub fn is_skip(&self) -> bool {
        matches!(self, LookupControlFlow::Skip)
    }

    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> LookupControlFlow<U, E> {
        match self {
            LookupControlFlow::Continue(Ok(value)) => LookupControlFlow::Continue(Ok(f(value))),
            LookupControlFlow::Continue(Err(err)) => LookupControlFlow::Continue(Err(err)),
            LookupControlFlow::Break(Ok(value)) => LookupControlFlow::Break(Ok(f(value))),
            LookupControlFlow::Break(Err(err)) => LookupControlFlow::Break(Err(err)),
            LookupControlFlow::Skip => LookupControlFlow::Skip,
        }
    }

    pub fn map_err<F, O: FnOnce(E) -> F>(self, f: O) -> LookupControlFlow<T, F> {
        match self {
            LookupControlFlow::Continue(Ok(value)) => LookupControlFlow::Continue(Ok(value)),
            LookupControlFlow::Continue(Err(err)) => LookupControlFlow::Continue(Err(f(err))),
            LookupControlFlow::Break(Ok(value)) => LookupControlFlow::Break(Ok(value)),
            LookupControlFlow::Break(Err(err)) => LookupControlFlow::Break(Err(f(err))),
            LookupControlFlow::Skip => LookupControlFlow::Skip,
        }
    }

    pub fn unwrap(self) -> T
    where
        E: fmt::Debug,
    {
        match self {
            LookupControlFlow::Continue(Ok(value)) | LookupControlFlow::Break(Ok(value)) => value,
            LookupControlFlow::Continue(Err(err)) | LookupControlFlow::Break(Err(err)) => {
                panic!("{:?}", err)
            }
            LookupControlFlow::Skip => panic!("skip"),
        }
    }

    pub fn expect(self, msg: &str) -> T
    where
        E: fmt::Debug,
    {
        match self {
            LookupControlFlow::Continue(Ok(value)) | LookupControlFlow::Break(Ok(value)) => value,
            LookupControlFlow::Continue(Err(err)) | LookupControlFlow::Break(Err(err)) => {
                panic!("{msg}: {:?}", err)
            }
            LookupControlFlow::Skip => panic!("{msg}: skip"),
        }
    }

    pub fn unwrap_err(self) -> E {
        match self {
            LookupControlFlow::Continue(Ok(_)) | LookupControlFlow::Break(Ok(_)) => {
                panic!("ok")
            }
            LookupControlFlow::Continue(Err(err)) | LookupControlFlow::Break(Err(err)) => err,
            LookupControlFlow::Skip => panic!("skip"),
        }
    }

    pub fn unwrap_or_default(self) -> T
    where
        T: Default,
    {
        match self {
            LookupControlFlow::Continue(Ok(value)) | LookupControlFlow::Break(Ok(value)) => value,
            _ => T::default(),
        }
    }

    pub fn into_result(self) -> Option<Result<T, E>> {
        match self {
            LookupControlFlow::Continue(Ok(value)) | LookupControlFlow::Break(Ok(value)) => {
                Some(Ok(value))
            }
            LookupControlFlow::Continue(Err(err)) | LookupControlFlow::Break(Err(err)) => {
                Some(Err(err))
            }
            LookupControlFlow::Skip => None,
        }
    }
}
