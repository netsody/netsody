[<img src="https://docs.drasyl.org/img/logo-text.svg" alt="drasyl" width="200"/>](https://drasyl.org)

[Website](https://drasyl.org) |
[Contributing](CONTRIBUTING.md) |
[Changelog](CHANGELOG.md)

[![Test](https://github.com/drasyl/drasyl-rs/actions/workflows/test.yml/badge.svg)](https://github.com/drasyl/drasyl-rs/actions/workflows/test.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/MIT)
[![Discord](https://img.shields.io/discord/959492172560891905)](https://discord.gg/2tcZPy7BCu)

# drasyl

drasyl ([dʁazy:l]) is a secure, software-defined overlay network built on [a fast, peer-to-peer protocol](./drasyl-p2p).
It enables you to interconnect all of your devices, making best use of the underlying physical network by using peer-to-peer technologies to create a mesh overlay.
Both centralized and distributed control planes are supported, offering fine-grained access control and optional gateways for bridging to external networks.
All traffic is encrypted and routed via the most direct physical path, bypassing NATs and firewalls.

## Features

- **Zero-Trust Security & Policy Enforcement**
    - End-to-end encryption by default
    - Device authentication & membership management
    - Fine-grained, endpoint-enforced communication policies

- **Decentralized, Controller-less Management**
    - No proprietary controller required
    - Human-readable TOML configuration (infrastructure as code)
        - Editable via any text editor
        - Guided editing via [web editor](https://editor.drasyl.org)
    - Distribution methods:
        - Central over HTTPS
        - Fully decentralized (each node holds a local copy)

- **Automation support**
    - Plain-text config enables automated updates:
        - Triggered by monitoring metrics
        - Integrates with CI/CD pipelines or custom scripts

- **Resilient Mesh Overlay Networking**
    - Native peer-to-peer with automatic NAT traversal
    - Fastest-relay fallback when direct paths fail
    - Protocol encapsulation to bypass UDP/port blocking

- **Multi-Homing & Administrative Domains**
    - Simultaneous membership in multiple drasyl overlays
    - Independent administrative domain and policy set per overlay

- **External-Network Gatewaying**
    - drasyl devices act as gateways to external subnets/services
    - Granular, per-resource access controls

- **Cross-Platform Support**
  - Production-ready on:
      - Windows
      - macOS
      - Linux
  - Planned targets:
      - iOS
      - Android
      - OpenWrt
      - Docker

# License

This is free software under the terms of the [MIT License](LICENSE).
