# cohesity-prometheus-exporter
A metrics collector that exports metrics from your local Cohesity cluster and outputs them in a format that can be ingested by Prometheus

## Overview

Use metrics from the Cohesity REST API to export relevant metrics to Prometheus

Install the Grafana dashboard by importing the JSON file `cohesity_grafana_dashboard.json`.

Fetch metrics:

```
curl http://CohesityCollector:1234/metrics
```

> Note: Metrics are fetched in a background worker after an initial scrape,
> since Cohesity can be slow to respond.
> Continue polling the `/metrics` endpoint until metrics are returned.

## Usage

```
docker pull ghcr.io/teebee-camx/cohesity-prometheus-exporter:<version>
```

## Prometheus.yml config

Add the following configuration to your prometheus.yml file to start scraping.

```
  - job_name: 'Cohesity exporter'
    static_configs:
      - targets: ['cohesity_exporter:1234']
    metrics_path: /metrics
```
