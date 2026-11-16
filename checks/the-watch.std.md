# The watch

| | |
| --- | --- |
| **Feature** | this Plugin against what Yoke last published |
| **Planning item** | yoke-project/yoke-plugin-network#1 |

## yoke-plugin-network:the-watch.01 — built and taken by the newest release of Yoke, the Plugin runs under its Core and answers its status

| Field | Value |
| --- | --- |
| **Cites** | specs/95.40 |
| **Level** | L3 |
| **Method** | check |
| **Not applicable in** | — |
| **Label** | blocking |
| **Precondition** | the newest published programs of Yoke; NetworkManager or not |
| **Action** | build the Plugin, take it into `try/`, run it, grant `network.status` and ask it |
| **Expected** | the instance comes up; the question is answered with a sequence where a manager runs, and failed as `unavailable` where none does |
