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

# Get Started

This guide walks you through setting up a drasyl network with two devices step by step.

## Step 1: Installation

Download and install drasyl for your operating systems:

### Linux (Debian/Ubuntu)

- **AMD64**: 
  - Daemon: [drasyl_0.1.0_amd64.deb](https://controller.drasyl.org/releases/0.1.0/linux-amd64/drasyl_0.1.0_amd64.deb)
  - UI: [drasyl-ui_0.1.0_amd64.deb](https://controller.drasyl.org/releases/0.1.0/linux-amd64/drasyl-ui_0.1.0_amd64.deb)
- **ARM64**: 
  - Daemon: [drasyl_0.1.0_arm64.deb](https://controller.drasyl.org/releases/0.1.0/linux-amd64/drasyl_0.1.0_arm64.deb)
  - UI: [drasyl-ui_0.1.0_arm64.deb](https://controller.drasyl.org/releases/0.1.0/linux-amd64/drasyl-ui_0.1.0_arm64.deb)

### macOS
- **Intel**: [drasyl_0.1.0_macos_x86_64.pkg](https://controller.drasyl.org/releases/0.1.0/macos-amd64/drasyl_0.1.0_macos_x86_64.pkg)
- **Apple Silicon**: [drasyl_0.1.0_macos_arm64.pkg](https://controller.drasyl.org/releases/0.1.0/macos-arm64/drasyl_0.1.0_macos_arm64.pkg)

### Windows
- **AMD64**: [drasyl_0.1.0_windows.exe](https://controller.drasyl.org/releases/0.1.0/windows-amd64/drasyl_0.1.0_windows.exe)

## Step 2: Collect Public Keys

1. **Start drasyl** on both devices
   - The application runs in the system tray (Windows/Linux) or menu bar (macOS)
   - A drasyl icon should appear in the taskbar

2. **Copy the Public Keys**:
   - Click on the drasyl tray icon
   - Select the first menu item (usually "Public Key: ..." or similar)
   - The public key is automatically copied to the clipboard
   - Note down both public keys for the next step

## Step 3: Configure Network

1. **Open the Web Editor**: [https://editor.drasyl.org](https://editor.drasyl.org)

2. **Create a new network**:
   - Choose a subnet (e.g., `10.0.0.0/24`)
   - Add both devices:
     - Click "Add Node"
     - Paste the public key of the first device and enter a hostname of your choice
     - Repeat for the second device

3. **Create a communication policy**:
   - Click "Add Policy"
   - Select "ALL <-> ALL" for unrestricted communication
   - Or create specific rules according to your needs

4. **Download configuration**:
   - Click "Get Config"
   - Save the `.toml` file locally

## Step 4: Deploy Network

**Option A: Local File (simple)**
- Copy the configuration file to both computers
- Use the path: `file:///path/to/configuration.toml`

**Option B: HTTP Server (recommended for easier distribution of configuration changes)**
- Upload the file to a web server
- Use the URL: `https://your-server.com/configuration.toml`

## Step 5: Join Network

1. **On both devices**:
   - Click on the drasyl tray icon
   - Select "Add Network..."
   - Enter the URL to the configuration file:
     - For local file: `file:///path/to/configuration.toml`
     - For web server: `https://your-server.com/configuration.toml`

2. **Test connection**:
   - After a few seconds, both nodes should be connected
   - Devices are reachable via the IP addresses specified in the configuration
   - Test the connection with `ping` or another network tool

## Next Steps

- **Set up Gateway**: Connect your drasyl network to the internet
- **Add more devices**: Repeat steps 2-5 for additional nodes
- **Advanced configuration**: Use the web editor for more complex network policies

## Help

If you encounter issues:
- Check firewall settings
- Ensure both devices have internet access
- Visit our [documentation](https://docs.drasyl.org) or [Discord](https://discord.gg/2tcZPy7BCu)

# License

This is free software under the terms of the [MIT License](LICENSE).
