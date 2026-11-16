//! netctl — command-line client for the network backend. Handy to exercise the
//! D-Bus communication, the event flow and the authorization (polkit) scope
//! without a UI.
//!
//! Read-only: devices | aps | profiles | permissions | watch
//! State-changing: scan | activate <uuid> | disconnect [device] | forget <uuid>

use std::sync::Arc;
use std::time::Instant;

use network::backend::{detect_backend, NetworkBackend, NetworkError};
use tokio::sync::{broadcast, mpsc};

const USAGE: &str = "usage: netctl <command>
  devices                 list network devices
  aps                     list Wi-Fi access points
  profiles                list saved profiles
  permissions             show what the current user is authorized to do
  watch                   print backend events until Ctrl-C
  scan                    request a Wi-Fi scan
  activate <uuid>         activate a saved profile
  disconnect [device]     disconnect the Wi-Fi (or the given) device
  forget <uuid>           delete a saved profile";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };

    let backend = match detect_backend().await {
        Ok(b)  => b,
        Err(e) => { eprintln!("no backend: {e}"); std::process::exit(1); }
    };

    if let Err(e) = run(backend, cmd, &args[1..]).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(b: Arc<dyn NetworkBackend>, cmd: &str, rest: &[String]) -> Result<(), NetworkError> {
    match cmd {
        "devices" => {
            for d in b.list_devices().await? {
                println!("{:<16} {:<9} {:<13} carrier={:<5} ip4={} gw={} dns=[{}]",
                    d.name, d.kind.as_str(), d.state.as_str(), d.carrier,
                    d.ip4.unwrap_or_else(|| "-".into()),
                    d.gw.unwrap_or_else(|| "-".into()),
                    d.dns.join(","));
            }
        }
        "aps" => {
            for a in b.list_access_points(None).await? {
                println!("{} {:<32} {:>3}%  ch{:<3} {}",
                    if a.in_use { '*' } else { ' ' },
                    a.ssid.unwrap_or_else(|| "(hidden)".into()),
                    a.signal_pct, a.channel, a.security.as_str());
            }
        }
        "profiles" => {
            for p in b.list_profiles().await? {
                println!("{}  {:<9} autoconnect={:<5} {}", p.uuid, p.kind.as_str(), p.autoconnect, p.id);
            }
        }
        "permissions" => {
            for p in b.permissions().await? {
                println!("{:<40} {}", p.action, p.result);
            }
        }
        "watch" => watch(b).await,
        "scan" => b.request_scan(None).await?,
        "activate" => {
            let uuid = rest.first().ok_or_else(|| NetworkError::Invalid("missing <uuid>".into()))?;
            let (tx, mut rx) = mpsc::channel::<network::backend::ProgressUpdate>(16);
            let printer = tokio::spawn(async move {
                while let Some(p) = rx.recv().await { println!("progress: {}", p.phase.as_str()); }
            });
            let res = b.activate_profile(uuid, None, "netctl".into(), tx).await;
            let _ = printer.await;
            println!("activated {}", res?);
        }
        "disconnect" => b.disconnect_wifi(rest.first().map(String::as_str)).await?,
        "forget" => {
            let uuid = rest.first().ok_or_else(|| NetworkError::Invalid("missing <uuid>".into()))?;
            b.forget_profile(uuid).await?;
        }
        _ => { eprintln!("{USAGE}"); std::process::exit(2); }
    }
    Ok(())
}

async fn watch(b: Arc<dyn NetworkBackend>) {
    let mut events = b.subscribe_signals();
    let t0 = Instant::now();
    println!("watching {} events, Ctrl-C to stop", b.name());
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            res = events.recv() => match res {
                Ok(ev) => println!("+{:>8.3}s  {}", t0.elapsed().as_secs_f32(), ev.describe()),
                Err(broadcast::error::RecvError::Lagged(n)) => println!("(missed {n} events)"),
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}
