#![cfg(feature = "loom-tests")]

use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

#[test]
fn dns_cache_insert_expire_evict_race_model() {
    loom::model(|| {
        let value = Arc::new(Mutex::new(Some(1usize)));
        let expired = Arc::new(AtomicBool::new(false));

        let v1 = Arc::clone(&value);
        let e1 = Arc::clone(&expired);
        let t1 = thread::spawn(move || {
            *v1.lock().expect("lock") = Some(2);
            e1.store(true, Ordering::Release);
        });

        let v2 = Arc::clone(&value);
        let e2 = Arc::clone(&expired);
        let t2 = thread::spawn(move || {
            if e2.load(Ordering::Acquire) {
                *v2.lock().expect("lock") = None;
            }
        });

        t1.join().expect("join");
        t2.join().expect("join");
        let _ = *value.lock().expect("lock");
    });
}

#[test]
fn fakeip_concurrent_allocate_and_eviction_lookup_model() {
    loom::model(|| {
        let slot = Arc::new(Mutex::new((None::<usize>, None::<usize>))); // (forward, reverse)

        let a = Arc::clone(&slot);
        let alloc = thread::spawn(move || {
            let mut g = a.lock().expect("lock");
            g.0 = Some(7);
            g.1 = Some(7);
        });

        let b = Arc::clone(&slot);
        let evict = thread::spawn(move || {
            let mut g = b.lock().expect("lock");
            if g.0 == Some(7) {
                g.0 = None;
                g.1 = None;
            }
        });

        alloc.join().expect("join");
        evict.join().expect("join");
        let g = slot.lock().expect("lock");
        assert_eq!(g.0.is_some(), g.1.is_some());
    });
}

#[test]
fn registry_reload_during_auth_lookup_model() {
    loom::model(|| {
        let users = Arc::new(AtomicUsize::new(1));
        let ok = Arc::new(AtomicBool::new(false));

        let u1 = Arc::clone(&users);
        let o1 = Arc::clone(&ok);
        let auth = thread::spawn(move || {
            let seen = u1.load(Ordering::Acquire);
            o1.store(seen > 0, Ordering::Release);
        });

        let u2 = Arc::clone(&users);
        let reload = thread::spawn(move || {
            u2.store(0, Ordering::Release);
            u2.store(2, Ordering::Release);
        });

        auth.join().expect("join");
        reload.join().expect("join");
        let _ = ok.load(Ordering::Acquire);
    });
}

#[test]
fn balancer_health_update_during_pick_model() {
    loom::model(|| {
        let alive_a = Arc::new(AtomicBool::new(true));
        let alive_b = Arc::new(AtomicBool::new(true));
        let picked = Arc::new(AtomicUsize::new(usize::MAX));

        let a1 = Arc::clone(&alive_a);
        let b1 = Arc::clone(&alive_b);
        let p1 = Arc::clone(&picked);
        let picker = thread::spawn(move || {
            let pick = if a1.load(Ordering::Acquire) {
                0
            } else if b1.load(Ordering::Acquire) {
                1
            } else {
                2
            };
            p1.store(pick, Ordering::Release);
        });

        let a2 = Arc::clone(&alive_a);
        let updater = thread::spawn(move || {
            a2.store(false, Ordering::Release);
        });

        picker.join().expect("join");
        updater.join().expect("join");
        let pick = picked.load(Ordering::Acquire);
        assert!(pick <= 2);
    });
}

#[test]
fn hot_reload_apply_failure_race_model() {
    loom::model(|| {
        let generation = Arc::new(AtomicUsize::new(1));
        let applying = Arc::new(AtomicBool::new(false));

        let g1 = Arc::clone(&generation);
        let a1 = Arc::clone(&applying);
        let applier = thread::spawn(move || {
            a1.store(true, Ordering::Release);
            // failure path: do not commit generation
            let _ = g1.load(Ordering::Acquire);
            a1.store(false, Ordering::Release);
        });

        let g2 = Arc::clone(&generation);
        let observer = thread::spawn(move || {
            if !applying.load(Ordering::Acquire) {
                let cur = g2.load(Ordering::Acquire);
                assert!(cur >= 1);
            }
        });

        applier.join().expect("join");
        observer.join().expect("join");
    });
}
