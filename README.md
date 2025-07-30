[<img src="https://docs.drasyl.org/img/logo-text.svg" alt="drasyl" width="200"/>](https://drasyl.org)

[Website](https://drasyl.org) |
[Documentation](https://docs.drasyl.org) |
[Contributing](CONTRIBUTING.md) |
[Changelog](CHANGELOG.md)

[![Test](https://github.com/drasyl/drasyl-rs/actions/workflows/test.yml/badge.svg)](https://github.com/drasyl/drasyl-rs/actions/workflows/test.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/MIT)
[![Discord](https://img.shields.io/discord/959492172560891905)](https://discord.gg/2tcZPy7BCu)

# drasyl

[drasyl](https://github.com/drasyl/drasyl-rs) ([dʁazy:l]) is a lightweight, software-defined overlay networking solution built on a [fast and secure peer-to-peer protocol](./drasyl-p2p).

It enables you to seamlessly interconnect all your devices in your organization, team, or home, regardless of typical network barriers prevalent between physical networks.
Unlike traditional VPNs, drasyl establishes direct, peer-to-peer connections between all devices, creating a mesh overlay that optimally utilizes the underlying physical network.
There is no need for a proprietary, centralized network controller, as overlay configurations can be distributed by any standard HTTP server or fully decentralized with local copies on each device.
You remain in control of network membership and permitted communication, following a zero-trust model with all traffic end-to-end encrypted and all devices authenticated.

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
        - Fully decentralized (each device holds a local copy)

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

- **Automation Support**
  - TOML config enables dynamic overlays driven by external inputs
  - e.g., an HTTP service aware of network metrics can serve adaptive configurations

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

# Get Started

Set up your first drasyl network in just a few minutes.
Our documentation guides you through the initial steps:

👉 [Get Started with drasyl](https://docs.drasyl.org/get-started)

# License

This is free software under the terms of the [MIT License](LICENSE).
