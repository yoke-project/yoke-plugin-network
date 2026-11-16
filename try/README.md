# Trying network

This directory is an application project that uses the Plugin in `..`: `yoke-compose init` made it and
`add plugin .. --yes` took the Plugin into it. Nothing here is the Plugin, and taking the Plugin into
another application never takes this directory.

| Path | What it is |
| --- | --- |
| `yoke.yaml` | the application: the unit `network` and the channel `panel`, a local socket for one client |
| `ui/` | the panel: an interface client written with Slint and the Rust interface library. It reaches the Plugin through the contract alone and links none of its code |
| `run.sh` | runs the application on a local Core, grants what the Plugin declares, and opens the panel |

```sh
./run.sh               # everything granted: the panel reads and acts
./run.sh --read-only   # no command granted: the panel reads, and the Core refuses every button
```

The panel subscribes to `network.status`, `network.devices` and `network.scan`, and starts those that do
not flow; it asks `network.status` once subscribed and drops what the stream brings at or below the
sequence it was answered with. Its Events tab shows the Core's events about the unit — its state, its
health, the occurrences it reports — and every change of the status. Closing the window stops the
streams the panel started.

What NetworkManager lets the account do is polkit's, apart from what the operator granted:
`network.permissions` says it, and `../plugin/policy/network.rules.example` is a rule for an account
that runs the Core as a service.

After a change to the Plugin, `run.sh` carries it again. To take it by hand:

    yoke-compose remove units.network
    rm components/plugins/network manifests/com.yoke.network.yaml
    yoke-compose add plugin ..
