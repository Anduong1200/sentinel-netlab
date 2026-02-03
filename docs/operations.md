# Operations Manual

## 1. Daily Maintenance

### Monitoring
- **Dashboard**: Check `http://<controller-ip>:8050` for real-time visualization.
- **Health Check**: `curl http://<controller-ip>:5000/api/v1/health`
- **Logs**: Monitor hardened services via Docker.
  ```bash
  docker compose -f ops/docker-compose.prod.yml logs -f controller
  ```

### Database Backups
- **PostgreSQL**: Use `pg_dump` on the `sentinel_db` container.
- **PCAPs**: Back up the `data/pcaps` volume.

## 2. Updates

### Controller Update
1.  Pull latest code or image.
2.  Restart hardened stack:
    ```bash
    docker compose -f ops/docker-compose.prod.yml up -d --build controller
    ```

## 3. CI/CD Security Gates

The project implements automated security gating in GitHub Actions:
- **Gitleaks**: Scans for accidental secret/token exposure.
- **Bandit**: Static Analysis Security Testing (SAST) for Python code.
- **Trivy**: Scans Docker images for OS and library vulnerabilities.
- **Lychee**: Validates all documentation links.

## 4. Production Performance
See [Resilience & Performance Guide](operations/resilience_and_performance.md) for self-healing logic and resource limits.

## 5. Security Rotation
See [Troubleshooting Runbook](operations/runbooks/troubleshooting.md) for HMAC/Secret rotation procedures.
