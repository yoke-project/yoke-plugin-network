//! network: the host's network manager as a Yoke Plugin unit.

use std::sync::Arc;
use std::time::Duration;

use network::backend::detect_backend;
use network::plugin::{declaration, handle, Net};
use tokio::sync::broadcast::error::RecvError;
use yoke_sdk::plugin::{start, Event};

/// How often the access points are emitted at most while they change, and the manager asked to scan
/// again, in ticks of the first.
const SCAN_TICK: Duration = Duration::from_secs(1);
const RESCAN_EVERY: u32 = 15;
/// How often the link is read while `network.link` flows.
const LINK_TICK: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() {
    // `network --manifest` prints the Manifest the declaration generates, which the bundle carries.
    if std::env::args().nth(1).as_deref() == Some("--manifest") {
        print!("{}", declaration().manifest());
        return;
    }
    let unit = match start(&declaration()).await {
        Ok(unit) => Arc::new(unit),
        Err(err) => {
            eprintln!("network: {err}");
            std::process::exit(1);
        }
    };
    // Registered: now the slower work, finding the manager. Without one the unit still runs, says why in
    // its health, and fails every question and command with the reason.
    let backend = detect_backend().await;
    let (grade, line) = match &backend {
        Ok(b) => (0, format!("{} connected", b.name())),
        Err(e) => (50, format!("no network manager: {e}")),
    };
    if let Err(err) = unit.health(grade, &line).await {
        eprintln!("network: {err}");
    }
    let mut said = backend.as_ref().ok().map(|b| b.subscribe_signals());
    let (net, mut steps) = Net::new(backend);
    // The status as the Plugin finds it: sequence 1, and no occurrence.
    if let Err(err) = net.refresh(unit.as_ref()).await {
        eprintln!("network: {err}");
    }
    // Nothing below wakes the unit on a clock unless `network.scan` flows.
    let mut tick = tokio::time::interval(SCAN_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let (mut ticks, mut dirty) = (0u32, false);
    // Nor is the link read unless `network.link` flows.
    let mut link_tick = tokio::time::interval(LINK_TICK);
    link_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("network listens for SIGTERM");
    loop {
        tokio::select! {
            event = unit.next() => match event {
                None | Some(Event::Ended(_)) => return,
                Some(Event::Activated(a)) => {
                    if let Err(err) = net.activated(unit.as_ref(), &a.stream).await {
                        eprintln!("network: {err}");
                    }
                }
                Some(Event::Stopped { stream }) => net.stopped(&stream),
                // Each on its own task: a connection that takes its time holds no other question or command.
                Some(event) => {
                    let (unit, net) = (unit.clone(), net.clone());
                    tokio::spawn(async move {
                        if let Err(err) = handle(unit.as_ref(), &event, &net).await {
                            eprintln!("network: {err}");
                        }
                    });
                }
            },
            ev = async { match said.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => match ev {
                Ok(ev) => match net.on_backend_event(unit.as_ref(), &ev).await {
                    Ok(access_points) => dirty |= access_points,
                    Err(err) => eprintln!("network: {err}"),
                },
                // Signals were missed: read everything again rather than trust what is held.
                Err(RecvError::Lagged(_)) => {
                    dirty = net.scanning();
                    if let Err(err) = net.refresh(unit.as_ref()).await {
                        eprintln!("network: {err}");
                    }
                }
                Err(RecvError::Closed) => {
                    said = None;
                    let _ = unit.health(50, "the network manager went away").await;
                }
            },
            Some(step) = steps.recv() => {
                if let Err(err) = net.on_progress(unit.as_ref(), &step).await {
                    eprintln!("network: {err}");
                }
            },
            _ = tick.tick(), if net.scanning() => {
                ticks += 1;
                if ticks % RESCAN_EVERY == 0 {
                    net.rescan().await;
                }
                if dirty {
                    dirty = false;
                    if let Err(err) = net.emit_scan(unit.as_ref()).await {
                        eprintln!("network: {err}");
                    }
                }
            },
            _ = link_tick.tick(), if net.linking() => {
                if let Err(err) = net.emit_link(unit.as_ref()).await {
                    eprintln!("network: {err}");
                }
            },
            _ = term.recv() => {
                // Asked to stop: close the Session in order, and leave once it has ended.
                let _ = unit.close().await;
                while let Some(event) = unit.next().await {
                    if matches!(event, Event::Ended(_)) {
                        break;
                    }
                }
                return;
            }
        }
    }
}
