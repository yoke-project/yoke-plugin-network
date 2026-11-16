# network

A Yoke Plugin that reads and drives the host's network through NetworkManager, with connman as a
fallback: the connection, the devices, the Wi-Fi networks in range, the saved profiles, a hotspot.

| | |
| --- | --- |
| questions | `network.status` (the connection, with its sequence), `network.devices`, `network.access-points`, `network.profiles`, `network.permissions` |
| commands | `network.wifi.scan`, `network.wifi.connect`, `network.wifi.disconnect`, `network.wifi.hotspot.start`, `network.wifi.hotspot.stop`, `network.profiles.activate`, `network.profiles.update`, `network.profiles.forget`, `network.ethernet.apply` |
| streams | `network.status`: every change of the connection and every step of one being made, none lost; `network.devices`: the devices, whole, at every change; `network.scan`: the access points in range, the manager asked to scan only while it flows |
| occurrences | `network.connected` (10), `network.disconnected` (30), `network.job.finished` when a command acknowledged as still running ends |

Every payload is JSON and states `schema`. A question takes `{}`, `network.access-points` an optional
`device`. A command's payload is the object its fields name; `network.wifi.connect` takes `ssid`,
`security` (`open`, `wep`, `wpa-psk`, `wpa2-psk`, `wpa3-psk`, `wpa-eap`, or `psk` and `eap`), `password`
or `eap`, and optionally `hidden`, `save_profile`, `device` and a `request_id` the steps on
`network.status` carry.

Every occurrence carries its facts as JSON in its detail — `line`, and the device, the network, the
command — which is what an interface client receives.

**An interface that attaches late** subscribes to `network.status`, then asks it, and drops what the
stream brings at or below the sequence it was answered with.

**A secret is handed to the manager and written nowhere**: no passphrase reaches a log line, an
acknowledgement or a failure's message.

Nothing is granted by declaring it: an operator grants the capabilities the Manifest names, one for
each question, command, stream and occurrence, and polkit still decides what the account may do with
NetworkManager — `network.permissions` says what it allows. `plugin/policy/network.rules.example` is a
rule for an account that runs the Core as a service.

`plugin/src/bin/netctl.rs` is a command-line client of the backend alone, with no Core.

Take it into an application with `yoke-compose add plugin https://github.com/yoke-project/yoke-plugin-network@<tag>`.
Build it with `yoke-compose build`, and try it from `try/`, which holds an application and a panel for it.

Licensed under the Apache License 2.0.
