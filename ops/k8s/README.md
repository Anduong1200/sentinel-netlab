# Kubernetes Deployment Guide

This directory contains manifests to deploy Sentinel NetLab on a Kubernetes cluster.

## Deployment Order

1.  **Setup (Namespace & Secrets)**
    Update the secrets in `00-setup.yaml` before applying.
    ```bash
    kubectl apply -f 00-setup.yaml
    ```

2.  **Infrastructure (Postgres & Redis)**
    ```bash
    kubectl apply -f 01-infra.yaml
    ```
    *Wait for pods to be ready.*

3.  **Controller (API)**
    ```bash
    kubectl apply -f 02-controller.yaml
    ```

4.  **Dashboard (UI & Ingress)**
    ```bash
    kubectl apply -f 03-dashboard.yaml
    ```

## Notes

- **Ingress**: The ingress assumes an Nginx Ingress Controller. Update `03-dashboard.yaml` `host` to match your domain.
- **Persistence**: The manifests use `volumeClaimTemplates` or `emptyDir` for simplicity. For production, ensure you have a default StorageClass or configure PVCs explicitly.
- **Images**: The manifests point to `ghcr.io/anduong1200/sentinel-*:latest`. Ensure these images are built and pushed, or update to your registry.
