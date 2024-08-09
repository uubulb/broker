# Broker for Nezha

A modified version of [Nezha Agent](https://github.com/nezhahq/agent), with features that shouldn't be in it.

## Difference from Nezha Agent
- Utilizes external data sources to report to **Nezha Dashboard**.
- Supports configuring multiple sources and connecting to multiple Dashboards.
- Currently supports only two task types: `TaskTypeCommand` and `TaskTypeTerminalGRPC`, implemented using SSH.

## Data collectors available
- [`nz-collector`](https://git.kuzu.uk/nz-collector.git/): A tiny system information collector for Linux systems.

You may add your own collector here if you like.

## TODOs
- Online documentation
- ~~Prometheus format~~
- Support other task types (unlikely)
- Telnet?

Feel free to contribute or provide feedback to help improve this project!

Note: This work is not officially endorsed by Nezha or its authors.
