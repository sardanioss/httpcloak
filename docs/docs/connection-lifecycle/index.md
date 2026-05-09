---
title: Connection Lifecycle
sidebar_position: 1
---

# Connection Lifecycle

Refresh, warmup, switch protocols, save and resume. Everything about how a session lives over time.

## In this section

- [Refresh](./refresh): drop every live connection but keep tickets, like a browser tab reload
- [Warmup](./warmup): multi-hop browser-style warmup before the actual request
- [Protocol Switching](./protocol-switching): switch H1 / H2 / H3 mid-session
- [Session Save and Restore](./session-save-restore): persist the whole session to disk, resume in another process
