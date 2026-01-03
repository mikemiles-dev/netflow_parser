use netflow_parser::{NetflowParser, TemplateEvent, TemplateProtocol};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn test_hook_registration() {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let _parser = NetflowParser::builder()
        .on_template_event(move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        })
        .build()
        .unwrap();

    // Hook is registered (count is still 0 until events are triggered)
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[test]
fn test_multiple_hooks() {
    let learned_count = Arc::new(AtomicUsize::new(0));
    let collision_count = Arc::new(AtomicUsize::new(0));
    let all_events_count = Arc::new(AtomicUsize::new(0));

    let lc = learned_count.clone();
    let cc = collision_count.clone();
    let ac = all_events_count.clone();

    let parser = NetflowParser::builder()
        .on_template_event(move |event| match event {
            TemplateEvent::Learned { .. } => {
                lc.fetch_add(1, Ordering::SeqCst);
            }
            TemplateEvent::Collision { .. } => {
                cc.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        })
        .on_template_event(move |_event| {
            ac.fetch_add(1, Ordering::SeqCst);
        })
        .build()
        .unwrap();

    // Manually trigger some events to test the hooks
    parser.trigger_template_event(TemplateEvent::Learned {
        template_id: 256,
        protocol: TemplateProtocol::V9,
    });

    parser.trigger_template_event(TemplateEvent::Collision {
        template_id: 300,
        protocol: TemplateProtocol::Ipfix,
    });

    parser.trigger_template_event(TemplateEvent::Learned {
        template_id: 400,
        protocol: TemplateProtocol::V9,
    });

    // First hook should have seen 2 learned events and 1 collision
    assert_eq!(learned_count.load(Ordering::SeqCst), 2);
    assert_eq!(collision_count.load(Ordering::SeqCst), 1);

    // Second hook should have seen all 3 events
    assert_eq!(all_events_count.load(Ordering::SeqCst), 3);
}

#[test]
fn test_hook_with_default_parser() {
    let event_count = Arc::new(AtomicUsize::new(0));
    let ec = event_count.clone();

    let parser = NetflowParser::builder()
        .on_template_event(move |_event| {
            ec.fetch_add(1, Ordering::SeqCst);
        })
        .build()
        .unwrap();

    // Trigger an event
    parser.trigger_template_event(TemplateEvent::MissingTemplate {
        template_id: 500,
        protocol: TemplateProtocol::Ipfix,
    });

    assert_eq!(event_count.load(Ordering::SeqCst), 1);
}

#[test]
fn test_hook_event_details() {
    let captured_id = Arc::new(AtomicUsize::new(0));
    let captured_protocol = Arc::new(std::sync::Mutex::new(None));

    let cid = captured_id.clone();
    let cp = captured_protocol.clone();

    let parser = NetflowParser::builder()
        .on_template_event(move |event| {
            if let TemplateEvent::Evicted {
                template_id,
                protocol,
            } = event
            {
                cid.store(*template_id as usize, Ordering::SeqCst);
                *cp.lock().unwrap() = Some(*protocol);
            }
        })
        .build()
        .unwrap();

    parser.trigger_template_event(TemplateEvent::Evicted {
        template_id: 1024,
        protocol: TemplateProtocol::V9,
    });

    assert_eq!(captured_id.load(Ordering::SeqCst), 1024);
    assert_eq!(
        *captured_protocol.lock().unwrap(),
        Some(TemplateProtocol::V9)
    );
}

#[test]
fn test_hook_builder_chaining() {
    let counter = Arc::new(AtomicUsize::new(0));
    let c1 = counter.clone();
    let c2 = counter.clone();

    let parser = NetflowParser::builder()
        .with_cache_size(2000)
        .on_template_event(move |_| {
            c1.fetch_add(1, Ordering::SeqCst);
        })
        .with_allowed_versions([5, 9, 10].into())
        .on_template_event(move |_| {
            c2.fetch_add(10, Ordering::SeqCst);
        })
        .build()
        .unwrap();

    parser.trigger_template_event(TemplateEvent::Expired {
        template_id: 200,
        protocol: TemplateProtocol::Ipfix,
    });

    // Both hooks should fire: +1 and +10
    assert_eq!(counter.load(Ordering::SeqCst), 11);
}

#[test]
fn test_parser_without_hooks() {
    // Parser should work fine without any hooks registered
    let parser = NetflowParser::default();

    // This should not panic or cause issues
    parser.trigger_template_event(TemplateEvent::Learned {
        template_id: 100,
        protocol: TemplateProtocol::V9,
    });
}

#[test]
fn test_hook_with_logging() {
    use std::sync::Mutex;

    let log = Arc::new(Mutex::new(Vec::new()));
    let log_clone = log.clone();

    let parser = NetflowParser::builder()
        .on_template_event(move |event| {
            let msg = match event {
                TemplateEvent::Learned {
                    template_id,
                    protocol,
                } => format!("Learned template {} ({:?})", template_id, protocol),
                TemplateEvent::Collision {
                    template_id,
                    protocol,
                } => format!("Collision on template {} ({:?})", template_id, protocol),
                TemplateEvent::Evicted {
                    template_id,
                    protocol,
                } => format!("Evicted template {} ({:?})", template_id, protocol),
                TemplateEvent::Expired {
                    template_id,
                    protocol,
                } => format!("Expired template {} ({:?})", template_id, protocol),
                TemplateEvent::MissingTemplate {
                    template_id,
                    protocol,
                } => format!("Missing template {} ({:?})", template_id, protocol),
            };
            log_clone.lock().unwrap().push(msg);
        })
        .build()
        .unwrap();

    parser.trigger_template_event(TemplateEvent::Learned {
        template_id: 256,
        protocol: TemplateProtocol::V9,
    });

    parser.trigger_template_event(TemplateEvent::Collision {
        template_id: 256,
        protocol: TemplateProtocol::V9,
    });

    parser.trigger_template_event(TemplateEvent::MissingTemplate {
        template_id: 300,
        protocol: TemplateProtocol::Ipfix,
    });

    let logged = log.lock().unwrap();
    assert_eq!(logged.len(), 3);
    assert!(logged[0].contains("Learned template 256"));
    assert!(logged[1].contains("Collision on template 256"));
    assert!(logged[2].contains("Missing template 300"));
}
