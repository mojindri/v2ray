//! proxy-app — application layer: routing, dispatching, DNS, and health checking.
//!
//! This crate is the "brain" of the proxy. It connects inbounds (where traffic
//! comes in) to outbounds (where traffic goes out) by:
//!
//!   1. **Routing**: deciding which outbound to use for a given connection,
//!      based on domain names, IP addresses, port numbers, and other attributes.
//!   2. **Dispatching**: actually relaying the bytes between the inbound
//!      connection and the outbound connection (bidirectional copy).
//!   3. **DNS**: resolving domain names, with optional FakeIP for TUN mode.
//!   4. **Health checking**: periodically testing outbounds and marking them
//!      dead when they fail, enabling automatic failover.

pub mod balancer;
pub mod context;
pub mod dispatcher;
pub mod dns;
pub mod features;
pub mod geo;
pub mod health;
pub mod metrics;
mod relay;
pub mod router;

pub use balancer::Balancer;
pub use context::Context;
pub use dispatcher::Dispatcher;
pub use features::{ConnectionHandler, InboundHandler, OutboundHandler};
pub use health::{HealthChecker, HealthStates, OutboundState};
pub use router::{Route, Router, RoutingContext};
