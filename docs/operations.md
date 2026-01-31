# Operations Manual

## 1. Daily Maintenance

### Monitoring
- **Dashboard**: Check `http://<controller-ip>:5000/dashboard` for sensor health status.
- **Logs**: Monitor standard output for `[CRITICAL]` or `[ERROR]` messages.
  ```bash
  docker logs -f sentinel-controller
  ```

### Database Backups
- **SQLite**: Copy `data/sentinel.db`.
- **PostgreSQL**: Use `pg_dump`.

## 2. Updates

### Controller Update
1.  Pull latest image:
    ```bash
    docker pull ghcr.io/anduong1200/sentinel-controller:latest
    ```
2.  Restart container:
    ```bash
    docker-compose -f ops/docker-compose.yml restart controller
    ```

## 3. CI/CD Security Gates

The project implements automated security gating in GitHub Actions:
- **Gitleaks**: Scans for accidental secret/token exposure.
- **Bandit**: Static Analysis Security Testing (SAST) for Python code.
- **Trivy**: Scans Docker images for OS and library vulnerabilities.
- **Lychee**: Validates all documentation links.

### Maintenance Note
If a Trivy scan fails due to a new CVE (e.g., OpenSSL), follow these steps to remediate:
1. Update the base image in `ops/Dockerfile.*`.
2. Add `apt-get upgrade -y` to pull the latest security patches.
3. Commit and push to trigger a fresh security-hardened build.

## 4. Security Rotation
See [Troubleshooting Runbook](operations/runbooks/troubleshooting.md) for HMAC/Secret rotation procedures.
