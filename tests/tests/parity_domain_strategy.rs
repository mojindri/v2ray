//! Routing `domainStrategy` wiring.

use blackwire_app::router::{LiveRouter, Router, RoutingContext};
use blackwire_common::{Address, Network};

#[test]
fn live_router_exposes_domain_strategy() {
    let router = LiveRouter::new(
        vec![],
        "direct",
        Default::default(),
        Default::default(),
        Some("UseIP".into()),
    );
    let ctx = RoutingContext {
        dest: &Address::Domain("example.com".into(), 443),
        network: Network::Tcp,
        inbound_tag: "in",
        user: None,
        sniffed_protocol: None,
        sniffed_domain: None,
    };
    let _ = router.pick_route(&ctx).unwrap();
    assert_eq!(router.domain_strategy().as_deref(), Some("UseIP"));
}
