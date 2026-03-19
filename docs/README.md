# Documentation: Sentinel NetLab

**Welcome to Sentinel NetLab Documentation.**

Sentinel NetLab is a specialized platform for WiFi security research and intrusion detection.

## 🚀 Choose Your Path

| I want to... | Profile | Recommended For |
| :--- | :--- | :--- |
| **Learn & Research** | **[Lab (Quickstart)](lab/quickstart.md)** | Developers, Researchers, Educational use. Uses SQLite, mock sensors, and offline-first mode. |
| **Deploy & Monitor** | **[Production](prod/deployment.md)** | Security Operations, Permanent deployment. Requires PostgreSQL, TLS, and secure secrets. |
| **Verify Features** | **[Testing Guide](lab/testing_guide.md)** | Step-by-step instructions to test Controller, Dashboard, Sensor, and Mock pipelines. |
| **Set up Hardware** | **[WiFi Drivers Guide](reference/wifi_drivers.md)** | Instruction to recognize, install, and troubleshoot Monitor Mode WiFi adapters. |

---

## 🔒 Security Principles

1.  **Lab Mode**: Defaults to `localhost` binding only. Databases and services are NOT exposed to the network. Secrets are auto-generated for convenience.
2.  **Production Mode**: Explicit configuration required. **TLS/SSL is mandatory** between components. Secrets must be provided via environment variables (fail-fast).
3.  **Offensive Capabilities**: Lab-only offensive modules (if installed) are strictly gated and will not run unless explicitly enabled in the profile configuration.

---

## 🔍 Scope: What's In / What's Out

| Feature | **Lab Profile** | **Prod Profile** |
| :--- | :--- | :--- |
| **Database** | SQLite (Embedded) | PostgreSQL + TimescaleDB |
| **Network** | Localhost (127.0.0.1) | Internal Network / Reverse Proxy |
| **Secrets** | Auto-generated (`.env.lab`) | Explicit ENV vars required |
| **Components** | Mock Sensor available | Real Sensors only |
| **Data** | Ephemeral (Reset allowed) | Persistent (Retention policies) |

---

## 📚 Reference Documentation

*   **[API Reference](reference/api.md)**: REST API contract, authentication, and endpoints.
*   **[Configuration](reference/configuration.md)**: Environment variables and profile settings.
*   **[Hardware & Software Requirements](reference/hardware_requirements.md)**: Detailed specs for CPU, RAM, OS Kernel, Storage, and Virtual Machines.
*   **[Database Schema](reference/schema.md)**: Data models and schema definitions.
*   **[Detection Pipeline](detection/overview.md)**: 11-detector architecture and pipeline diagram.
*   **[TUI Command Center](lab/tui_guide.md)**: Terminal dashboard user guide and architecture.
*   **[Legal & Ethics](reference/legal_ethics.md)**: Authorization, consent, and data handling.

---

### Support

*   **Issues**: Please file bug reports on GitHub.
*   **Security**: Report security vulnerabilities via our private disclosure program.
*   **Status**: Profile support: `lab` (Stable), `prod` (Stable).
