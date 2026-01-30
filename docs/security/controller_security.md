# Controller Security

The Controller is the central nervous system and requires strict security controls.

## 1. Authentication & Authorization
- **RBAC Model**:
  - `ADMIN`: Full access (Config, User mgmt).
  - `ANALYST`: Read-only (Dashboard, Reports).
  - `OPERATOR`: Sensor management (Revoke/Approve).
  - `SENSOR`: Telemetry write-only.
- **Implementation**: Flask middleware `require_auth` + Database-backed Tokens.

## 2. Isolation
- **Docker**: Controller runs in a container with no privileged capabilities.
- **Network**: Database is not exposed publicly; only accessible by Controller container.
- **Redis**: Password-protected, internal network only.

## 3. Rate Limiting
DoS protection using `Flask-Limiter` with Redis backend.
- **API**: 100 requests/minute per IP/Token.
- **Auth**: 5 failed login attempts per hour (Account Lockout).

## 4. Input Validation
- All inputs validated against **Pydantic Schemas** (`common/schemas`).
- Invalid JSON or schema violations rejected with `400 Bad Request`.
- SQL Injection protected via SQLAlchemy ORM (parameterized queries).
