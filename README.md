# Broker for Nezha

Yet another client for Nezha.

## Documentation
<https://broker.kuzu.uk/>

## Difference from Nezha Agent
- Utilizes external data sources to report to **Nezha Dashboard**.
- Supports configuring multiple sources and connecting to multiple Dashboards.

Currently, Broker supports the following tasks:
- `TaskTypeCommand`: Execute commands on a remote server via SSH.
- `TaskTypeTerminalGRPC`: Open a shell on a remote server via SSH.
- `TaskTypeReportHostInfo`: Trigger a report when Dashboard restarts.
- `TaskTypeFM`: Transfer files via SFTP.

Other tasks that involve collecting data from local machine are not supported and should be handled directly using Nezha Agent.

## Data collectors available
- [`nz-collector`](https://codeberg.org/uubulb/nz-collector): A tiny system information collector for Linux systems.

You may add your own collector here if you like.

## TODOs
- Support virtualization platform APIs like Proxmox VE, incus...
- An interactive configuration editor
- Telnet?

Note: This work is not officially endorsed by Nezha or its authors.
