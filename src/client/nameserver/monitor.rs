use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::{Duration, Instant},
};

use hickory_proto::xfer::Protocol;
use pin_project::pin_project;

use crate::client::{DnsClientError, codec::TaggedMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityTier {
    Connected = 1,
    Connectionless,
    NotConnected,
    Failing,
}

impl fmt::Display for PriorityTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PriorityTier::Connected => write!(f, "Connected"),
            PriorityTier::Connectionless => write!(f, "Connectionless"),
            PriorityTier::NotConnected => write!(f, "NotConnected"),
            PriorityTier::Failing => write!(f, "Failing"),
        }
    }
}

#[derive(Debug)]
pub struct SmoothedTimer {
    srtt_microseconds: AtomicU32,
    start: Instant,
    last_update: AtomicU32,
}

impl PartialEq for SmoothedTimer {
    fn eq(&self, other: &Self) -> bool {
        debug_assert!(!self.current().is_nan());
        debug_assert!(!other.current().is_nan());
        self.current() == other.current()
    }
}

impl Eq for SmoothedTimer {}

impl PartialOrd for SmoothedTimer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SmoothedTimer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        debug_assert!(!self.current().is_nan());
        debug_assert!(!other.current().is_nan());
        self.current()
            .partial_cmp(&other.current())
            .expect("srtt is NaN")
    }
}

// Generally, fast DNS should respond in less than 50ms, so this will hunt for servers that can do at least this good.
const BASELINE_RESPONSE_MS: u32 = 50;

impl Default for SmoothedTimer {
    fn default() -> Self {
        Self {
            srtt_microseconds: AtomicU32::new(BASELINE_RESPONSE_MS),
            start: Instant::now(),
            last_update: AtomicU32::new(0),
        }
    }
}

impl SmoothedTimer {
    /// Create a new `SmoothedTimer` with the given initial SRTT.
    #[allow(dead_code)]
    pub fn new(initial_srtt: Duration) -> Self {
        Self {
            srtt_microseconds: AtomicU32::new(initial_srtt.as_micros() as u32),
            start: Instant::now(),
            last_update: AtomicU32::new(0),
        }
    }

    pub fn record(&self, rtt: Duration) {
        // If the cast on the result does overflow (it shouldn't), then the
        // value is saturated to u32::MAX, which is above the `MAX_SRTT_MICROS`
        // limit (meaning that any potential overflow is inconsequential).
        // See https://github.com/rust-lang/rust/issues/10184.
        self.update(
            rtt.as_micros() as u32,
            |cur_srtt_microseconds, since_last_update| {
                // An arbitrarily low weight is used when computing the factor
                // to ensure that recent RTT measurements are weighted more
                // heavily.
                let factor = compute_srtt_factor(since_last_update, Self::UPDATE_WEIGHT);
                let new_srtt = (1.0 - factor) * (rtt.as_micros() as f64)
                    + factor * f64::from(cur_srtt_microseconds);
                new_srtt.round() as u32
            },
        );
    }

    fn since_last_update(&self, instant: Instant) -> f64 {
        instant.saturating_duration_since(self.start).as_secs_f64()
            - (self.last_update.load(Ordering::Acquire) as f64)
    }

    /// Returns the SRTT value after applying a time based decay.
    ///
    /// The decay exponentially decreases the SRTT value. The primary reasons
    /// for applying a downwards decay are twofold:
    ///
    /// 1. It helps distribute query load.
    /// 2. It helps detect positive network changes. For example, decreases in
    ///    latency or a server that has recovered from a failure.
    pub fn current(&self) -> f64 {
        let srtt = f64::from(self.srtt_microseconds.load(Ordering::Acquire));

        let last_update = self.last_update.load(Ordering::Acquire);
        if last_update == 0 {
            return srtt;
        }

        let since_last_update = self.start.elapsed().as_secs_f64() - (last_update as f64);

        srtt * compute_srtt_factor(since_last_update, Self::DECAY_WEIGHT)
    }

    /// Updates the SRTT value.
    ///
    /// If the `last_update` value has not been set, then uses the `default`
    /// value to update the SRTT. Otherwise, invokes the `update_fn` with the
    /// current SRTT value and the `last_update` timestamp.
    fn update(&self, default: u32, update_fn: impl Fn(u32, f64) -> u32) {
        let use_default = self.last_update.load(Ordering::Acquire) == 0;
        let last_update = self.since_last_update(Instant::now());
        let _ = self.srtt_microseconds.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            move |cur_srtt_microseconds| {
                Some(
                    if use_default {
                        default
                    } else {
                        update_fn(cur_srtt_microseconds, last_update)
                    }
                    .min(Self::MAX_SRTT_MICROS),
                )
            },
        );
    }

    const MAX_SRTT_MICROS: u32 = Duration::from_secs(5).as_micros() as u32;
    const DECAY_WEIGHT: u32 = 180;
    const UPDATE_WEIGHT: u32 = 3;
}

/// Returns an exponentially weighted value in the range of 0.0 < x < 1.0
///
/// Computes the value using the following formula:
///
/// e<sup>(-t<sub>now</sub> - t<sub>last</sub>) / weight</sup>
///
/// As the duration since the `last_update` approaches the provided `weight`,
/// the returned value decreases.
fn compute_srtt_factor(last_update: f64, weight: u32) -> f64 {
    let exponent = (-last_update.max(1.0)) / f64::from(weight);
    exponent.exp()
}

// pub struct ServiceTimer<S> {
//     service: S,
//     timer: Arc<SmoothedTimer>,
// }

// impl<S> ServiceTimer<S> {
//     pub fn new(service: S) -> Self {
//         Self {
//             service,
//             timer: Arc::new(SmoothedTimer::default()),
//         }
//     }
// }

// impl<S, R> tower::Service<R> for ServiceTimer<S>
// where
//     S: tower::Service<R>,
// {
//     type Response = S::Response;
//     type Error = S::Error;
//     type Future = ServiceTimerFuture<S::Future>;

//     fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         self.service.poll_ready(cx)
//     }

//     fn call(&mut self, request: R) -> Self::Future {
//         let start = Instant::now();
//         let future = self.service.call(request);
//         ServiceTimerFuture {
//             future,
//             start,
//             timer: self.timer.clone(),
//         }
//     }
// }

// #[pin_project]
// pub struct ServiceTimerFuture<F> {
//     #[pin]
//     future: F,
//     start: Instant,
//     timer: Arc<SmoothedTimer>,
// }

// impl<F, T, E> Future for ServiceTimerFuture<F>
// where
//     F: Future<Output = Result<T, E>>,
// {
//     type Output = Result<T, E>;

//     fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         let this = self.project();
//         let result = ready!(this.future.poll(cx));
//         if result.is_ok() {
//             this.timer.record(this.start.elapsed());
//         }
//         Poll::Ready(result)
//     }
// }

#[derive(Debug)]
pub(crate) struct AtomicPriorityTier(AtomicUsize);

impl PartialEq for AtomicPriorityTier {
    fn eq(&self, other: &Self) -> bool {
        self.0.load(Ordering::Relaxed) == other.0.load(Ordering::Relaxed)
    }
}

impl Eq for AtomicPriorityTier {}

impl Ord for AtomicPriorityTier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .load(Ordering::Relaxed)
            .cmp(&other.0.load(Ordering::Relaxed))
    }
}

impl PartialOrd for AtomicPriorityTier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AtomicPriorityTier {
    pub(crate) fn new(tier: PriorityTier) -> Self {
        Self(AtomicUsize::new(tier as usize))
    }

    pub(crate) fn for_protocol(protocol: &Protocol) -> Self {
        match protocol {
            Protocol::Udp => Self::new(PriorityTier::Connectionless),
            _ => Self::new(PriorityTier::NotConnected),
        }
    }

    pub(crate) fn get(&self) -> PriorityTier {
        match self.0.load(Ordering::Relaxed) {
            1 => PriorityTier::Connected,
            2 => PriorityTier::Connectionless,
            3 => PriorityTier::NotConnected,
            4 => PriorityTier::Failing,
            _ => unreachable!(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn reset(&self, protocol: &Protocol) {
        match protocol {
            Protocol::Udp => self.set(PriorityTier::Connectionless),
            _ => self.set(PriorityTier::NotConnected),
        }
    }

    pub(crate) fn failed(&self) {
        self.set(PriorityTier::Failing);
    }

    pub(crate) fn connected(&self, protocol: &Protocol) {
        match protocol {
            Protocol::Udp => self.set(PriorityTier::Connectionless),
            _ => self.set(PriorityTier::Connected),
        }
    }

    pub(crate) fn set(&self, tier: PriorityTier) {
        self.0.store(tier as usize, Ordering::Relaxed);
    }

    pub fn response(self: &Arc<AtomicPriorityTier>, protocol: &Protocol) -> ResponsePriority {
        ResponsePriority::new(self.clone(), protocol.clone())
    }
}

#[derive(Debug, Clone)]
pub struct ResponsePriority {
    inner: Arc<AtomicPriorityTier>,
    protocol: Protocol,
}

impl ResponsePriority {
    pub fn new(inner: Arc<AtomicPriorityTier>, protocol: Protocol) -> Self {
        Self { inner, protocol }
    }

    pub fn connected(&self) {
        self.inner.connected(&self.protocol);
    }

    pub fn error(&self) {
        self.inner.failed();
    }

    pub fn set<T, E>(&self, result: &Result<T, E>) {
        match result {
            Ok(_) => self.connected(),
            Err(_) => self.error(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Activity(Arc<AtomicUsize>);

impl Activity {
    pub fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(0)))
    }

    pub fn acquire(&self) -> ActivityGuard {
        self.0.fetch_add(1, Ordering::Relaxed);
        ActivityGuard(self.0.clone())
    }
}

impl Ord for Activity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .load(Ordering::Relaxed)
            .cmp(&other.0.load(Ordering::Relaxed))
    }
}

impl PartialOrd for Activity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Activity {
    fn eq(&self, other: &Self) -> bool {
        self.0.load(Ordering::Relaxed) == other.0.load(Ordering::Relaxed)
    }
}

impl Eq for Activity {}

#[derive(Debug)]
pub struct ActivityGuard(Arc<AtomicUsize>);

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    priority: Arc<AtomicPriorityTier>,
    roundtriptime: Arc<SmoothedTimer>,
    active: Activity,
}

impl ConnectionStats {
    pub fn new(protocol: &Protocol) -> Self {
        Self {
            priority: Arc::new(AtomicPriorityTier::for_protocol(protocol)),
            roundtriptime: Arc::new(SmoothedTimer::default()),
            active: Activity::new(),
        }
    }

    pub fn priority(&self) -> PriorityTier {
        self.priority.get()
    }

    pub fn srtt(&self) -> Duration {
        Duration::from_millis(self.roundtriptime.current() as u64)
    }
}

impl PartialEq for ConnectionStats {
    fn eq(&self, other: &Self) -> bool {
        self.priority.get() == other.priority.get()
            && self.active == other.active
            && self.roundtriptime == other.roundtriptime
    }
}

impl Eq for ConnectionStats {}

impl PartialOrd for ConnectionStats {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConnectionStats {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority
            .get()
            .cmp(&other.priority.get())
            .then(self.active.cmp(&other.active))
            .then(self.roundtriptime.cmp(&other.roundtriptime))
    }
}

#[derive(Debug, Clone)]
pub struct MonitoredConnection<S> {
    service: S,
    monitor: ConnectionStats,
    protocol: Protocol,
}

impl<S> MonitoredConnection<S> {
    pub fn new(service: S, protocol: &Protocol) -> Self {
        Self {
            service,
            monitor: ConnectionStats::new(protocol),
            protocol: protocol.clone(),
        }
    }

    pub fn monitor(&self) -> &ConnectionStats {
        &self.monitor
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    #[allow(dead_code)]
    pub fn inner(&self) -> &S {
        &self.service
    }
}

impl<S> tower::Service<TaggedMessage> for MonitoredConnection<S>
where
    S: tower::Service<TaggedMessage, Response = TaggedMessage, Error = DnsClientError>,
{
    type Response = TaggedMessage;
    type Error = DnsClientError;
    type Future = MonitoredFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: TaggedMessage) -> Self::Future {
        MonitoredFuture::new(self.service.call(req), &self.monitor, &self.protocol)
    }
}

#[pin_project]
pub struct MonitoredFuture<F> {
    #[pin]
    future: F,
    activity: Option<ActivityGuard>,
    priority: Option<ResponsePriority>,
    speed: Arc<SmoothedTimer>,
    started: Instant,
}

impl<F> MonitoredFuture<F> {
    fn new(future: F, monitor: &ConnectionStats, protocol: &Protocol) -> Self {
        let activity = Some(monitor.active.acquire());
        let priority = Some(monitor.priority.response(protocol));
        let speed = monitor.roundtriptime.clone();
        Self {
            future,
            activity,
            priority,
            speed,
            started: Instant::now(),
        }
    }
}

impl<F, T, E> Future for MonitoredFuture<F>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = F::Output;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result = ready!(this.future.poll(cx));
        if result.is_ok() {
            this.speed.record(this.started.elapsed());
        }
        this.priority.take().map(|p| p.set(&result));
        this.activity.take();
        Poll::Ready(result)
    }
}
