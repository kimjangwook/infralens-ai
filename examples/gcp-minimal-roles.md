# GCP minimal permissions

For the MVP scanner, grant a service account read access to:

- Cloud Scheduler jobs
- Cloud Run viewer
- Cloud Logging viewer

Cost anomaly scanning will require BigQuery Billing Export access in a later version.

