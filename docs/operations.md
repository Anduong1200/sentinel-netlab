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
    docker-compose restart controller
    ```

## 3. Security Rotation
See [Troubleshooting Runbook](operations/runbooks/troubleshooting.md) for HMAC/Secret rotation procedures.
