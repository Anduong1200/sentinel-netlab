# Lab Safety & Scope

> **⚠️ This is a LAB environment - for learning and authorized testing only.**

---

## Intended Use

Sentinel NetLab Lab Mode is designed for:

- ✅ **Learning** - Understand wireless threat detection concepts
- ✅ **Training** - Practice SOC analyst workflows
- ✅ **Development** - Test detector algorithms safely
- ✅ **Demos** - Show product capabilities offline

---

## NOT Intended For

- ❌ **Production security monitoring**
- ❌ **Real-world threat detection**
- ❌ **Capturing traffic on networks you don't own**
- ❌ **Compliance/audit evidence**

---

## Safety Features

| Feature | Lab Behavior | Why |
|---------|--------------|-----|
| **Mock Sensor** | `SENSOR_MOCK_MODE=true` | No hardware required |
| **Network Binding** | `127.0.0.1` only | Not exposed externally |
| **Database** | SQLite (ephemeral) | Easy reset, no persistence |
| **Auth** | Auto-generated tokens | Simplified access |
| **TLS** | Disabled | Localhost only |

---

## Offline-First

Lab Mode is designed to work **completely offline**:

- No external API calls
- No cloud dependencies
- No internet required after initial `docker pull`
- All demo data included in `examples/`

---

## Legal Disclaimer

> **By using Lab Mode, you acknowledge:**
>
> 1. You will only capture wireless traffic on networks you own or have explicit authorization to monitor.
> 2. This tool is for educational purposes in controlled environments.
> 3. Unauthorized wireless monitoring may violate local laws.

---

## Transitioning to Production

When ready for real deployment, use the **Production Guide**:

📖 [docs/prod/deployment.md](../prod/deployment.md)

Key differences:
- `SENTINEL_PROFILE=prod` enforces security
- Postgres/Timescale required
- TLS mandatory
- Real sensor hardware needed
