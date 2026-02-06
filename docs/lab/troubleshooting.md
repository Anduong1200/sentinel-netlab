# Sentinel NetLab - Lab Troubleshooting

Common issues and solutions for the Lab environment.

---

## 1. Containers Won't Start

**Symptoms**: `make lab-up` fails, containers exit immediately.

**Diagnosis**:
```bash
cd ops && docker-compose -f docker-compose.lab.yml logs
```

**Common Causes**:

| Error Message                          | Solution                                      |
|----------------------------------------|-----------------------------------------------|
| `port is already allocated`            | Stop conflicting service or edit `.env.lab`   |
| `network sentinel-lab-net not found`   | Run `docker network create sentinel-lab-net`  |
| `secret not set`                       | Run `python ops/gen_lab_secrets.py`           |
| `POSTGRES_PASSWORD required`           | Check `ops/.env.lab` exists and is populated  |

---

## 2. Dashboard Shows No Data

**Symptoms**: Dashboard loads but shows "No sensors" or "No alerts".

**Solution**:
```bash
make lab-reset
```

This wipes the database and seeds fresh demo data.

**Alternative** (manual seed):
```bash
python ops/seed_lab_data.py
```

---

## 3. Cannot Login to Dashboard

**Symptoms**: Basic Auth prompt, credentials rejected.

**Check Credentials**:
```bash
cat ops/.env.lab | grep DASH
```

Look for `DASH_USERNAME` and `DASH_PASSWORD`. Use these to log in.

**Regenerate Secrets**:
```bash
rm ops/.env.lab
python ops/gen_lab_secrets.py
make lab-reset
```

---

## 4. Controller API Returns 500

**Symptoms**: API calls fail with Internal Server Error.

**Diagnosis**:
```bash
docker logs sentinel-lab-controller
```

**Common Causes**:

| Log Message                            | Solution                                      |
|----------------------------------------|-----------------------------------------------|
| `CRITICAL: Missing required...`        | Missing secret in `.env.lab`. Regenerate.     |
| `database connection refused`          | Postgres not healthy. Check `docker logs sentinel-lab-postgres`. |
| `table does not exist`                 | DB not initialized. Run `python ops/init_lab_db.py`. |

---

## 5. Sensor Not Sending Data

**Symptoms**: Sensor container runs but no telemetry in Dashboard.

**Check Sensor Logs**:
```bash
docker logs sentinel-lab-sensor
```

**Possible Issues**:
- `SENSOR_AUTH_TOKEN` mismatch. Ensure `.env.lab` has the correct token.
- `SENSOR_MOCK_MODE` is `false` but no hardware available. Set to `true`.

---

## 6. High Memory / CPU Usage

**Symptoms**: System slow, Docker using excessive resources.

**Mitigation**:
- Reduce worker concurrency in `docker-compose.lab.yml`.
- Limit container resources:
  ```yaml
  deploy:
    resources:
      limits:
        memory: 512M
  ```

---

## 7. Data Corruption After Update

**Symptoms**: Errors after pulling new code.

**Solution**: Full reset.
```bash
make lab-reset
```

If issues persist, prune Docker volumes:
```bash
docker volume rm $(docker volume ls -qf "name=sentinel-lab")
make lab-up
```

---

## Getting Help

If none of the above works:

1. Check GitHub Issues: [sentinel-netlab/issues](https://github.com/anduong1200/sentinel-netlab/issues)
2. Open a new issue with:
   - Output of `make lab-logs`
   - Your OS and Docker version
   - Steps to reproduce

---

*Last updated: 2026-02-06*
