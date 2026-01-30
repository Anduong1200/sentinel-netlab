# System Trust Model

## 1. Trust Boundaries

The system is designed with strict isolation between components to minimize blast radius in case of compromise.

```mermaid
graph TD
    subgraph "Untrusted Zone"
        WiFi[WiFi Environment]
        Internet[Internet]
        Attacker[Attacker]
    end

    subgraph "DMZ / Sensor Zone"
        Adapter[WiFi Adapter<br/>(Monitor Mode)]
        Sensor[Sensor Process]
    end

    subgraph "Controller Zone"
        API[API Server<br/>(Flask)]
        DB[(Database<br/>Postgres)]
        Redis[Redis Cache]
    end

    subgraph "Operator Zone"
        Dash[Dashboard<br/>Web]
        Analyst[Analyst Console]
    end

    %% Data Flows
    WiFi -->|802.11 Frames| Adapter
    Adapter -->|Raw Data| Sensor
    Sensor -->|HTTPS/mTLS + HMAC| API
    
    %% Internal Controller Flows
    API -->|Auth/RBAC| DB
    API -->|Queue| Redis
    
    %% Operator Flows
    Dash -->|HTTPS| API
    Analyst -->|HTTPS| API

    %% Trust Boundaries
    linkStyle 2 stroke:red,stroke-width:2px,stroke-dasharray: 5 5;
    linkStyle 3 stroke:red,stroke-width:2px,stroke-dasharray: 5 5;
```

## 2. Component Trust Levels

### Sensor (Low Trust)
- **Role**: Data collection and initial filtering.
- **Access**: Can only write telemetry/alerts to API. Cannot read other sensors' data.
- **Risk**: Physically accessible (if deployed remotely), vulnerable to 802.11 exploits.
- **Constraint**: Treated as potentially compromised. No persistent secrets beyond API token/HMAC key.

### Controller (High Trust)
- **Role**: Data aggregation, correlation, and storage.
- **Access**: Full database access.
- **Risk**: Central target for poisoning or DoS.
- **Constraint**: Must validate all inputs from sensors strictly.

### Dashboard (Medium Trust)
- **Role**: Visualization and management.
- **Access**: Read-only mostly, some write for config (Admin only).
- **Control**: Authenticated via OIDC/OAuth in production (or Strong Auth).
