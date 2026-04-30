#!/usr/bin/env python3
"""
Cohesity Prometheus/OpenMetrics exporter

Design goals:
- Fast scrape path: /metrics serves cached rendered bytes.
- Background refresh gathers Cohesity data.
- Direct bearer-token auth against /irisservices/api/v1/public/accessTokens.
- V2-first cluster discovery/stats where possible.
- V1/public fallbacks for endpoints already known to work in many clusters.
- True OpenMetrics output with # EOF.
"""

import argparse
import os
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
from prometheus_client import CollectorRegistry
from prometheus_client.core import GaugeMetricFamily
from prometheus_client import ProcessCollector, PlatformCollector, GCCollector
from prometheus_client.openmetrics.exposition import generate_latest

requests.packages.urllib3.disable_warnings()

DEBUG = os.environ.get("CPE_DEBUG", "1").lower() not in ["0", "false", "no", "off"]
REFRESH_SECONDS = int(os.environ.get("CPE_REFRESH_SECONDS", "60"))

# Independent cache refresh intervals.
# /metrics always serves cached rendered output; these control how often each Cohesity API family is refreshed.
CLUSTER_REFRESH_SECONDS = int(os.environ.get("CPE_CLUSTER_REFRESH_SECONDS", "60"))
ALERTS_REFRESH_SECONDS = int(os.environ.get("CPE_ALERTS_REFRESH_SECONDS", "120"))
JOBS_REFRESH_SECONDS = int(os.environ.get("CPE_JOBS_REFRESH_SECONDS", "600"))
SOURCES_REFRESH_SECONDS = int(os.environ.get("CPE_SOURCES_REFRESH_SECONDS", "600"))
JOB_RUNS_REFRESH_SECONDS = int(os.environ.get("CPE_JOB_RUNS_REFRESH_SECONDS", "600"))
NODE_STATS_REFRESH_SECONDS = int(os.environ.get("CPE_NODE_STATS_REFRESH_SECONDS", "300"))

# Confirmed batched v1 public node stats endpoint:
# /irisservices/api/v1/public/nodes?fetchStats=true
CPE_ENABLE_NODE_STATS = os.environ.get("CPE_ENABLE_NODE_STATS", "1").lower() not in ["0", "false", "no", "off"]
RUN_WORKERS = int(os.environ.get("CPE_RUN_WORKERS", "8"))
INCLUDE_JOB_RUNS = os.environ.get("CPE_INCLUDE_JOB_RUNS", "1").lower() not in ["0", "false", "no", "off"]
REQUEST_TIMEOUT = int(os.environ.get("CPE_REQUEST_TIMEOUT", "60"))
STATS_ENABLED = os.environ.get("CPE_STATS_ENABLED", "1").lower() not in ["0", "false", "no", "off"]
STATS_LOOKBACK_SECONDS = int(os.environ.get("CPE_STATS_LOOKBACK_SECONDS", "3600"))


def log(message):
    if DEBUG:
        print(f"[cpe] {message}", flush=True)


def warn(message):
    print(f"[cpe][warn] {message}", flush=True)


def err(message):
    print(f"[cpe][error] {message}", flush=True)


parser = argparse.ArgumentParser()
parser.add_argument("-v", "--vip", type=str, required=True)
parser.add_argument("-u", "--username", type=str, required=True)
parser.add_argument("-d", "--domain", type=str, default="local")
parser.add_argument("-pwd", "--password", type=str, default=None)
parser.add_argument("-c", "--clustername", type=str, default=None)
parser.add_argument("-m", "--minutes", type=int, default=60)
parser.add_argument("-port", "--port", type=int, default=1234)
parser.add_argument("-k", "--useApiKey", action="store_true")
args = parser.parse_args()

vip = args.vip
username = args.username
domain = args.domain
password = args.password
clustername = args.clustername
minutes = args.minutes
port = args.port
useApiKey = args.useApiKey

log(
    f"startup vip={vip} username={username} domain={domain} "
    f"clustername={clustername} port={port} useApiKey={useApiKey} "
    f"password_set={password is not None} refresh_seconds={REFRESH_SECONDS} "
    f"run_workers={RUN_WORKERS} include_job_runs={INCLUDE_JOB_RUNS} "
    f"stats_enabled={STATS_ENABLED}"
)


def _to_float(value, default=0.0):
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _to_int(value, default=0):
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _first_present(dct, keys, default=None):
    if not isinstance(dct, dict):
        return default
    for key in keys:
        if key in dct and dct[key] is not None:
            return dct[key]
    return default


def _label_safe(value):
    if value is None:
        return "unknown"
    return str(value)


def _walk_list(payload):
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in [
            "items", "entities", "data", "jobs", "alerts", "nodes",
            "sources", "protectionGroups", "protectionRuns",
            "protectionJobs", "protectionSources", "objects"
        ]:
            if key in payload and isinstance(payload[key], list):
                return payload[key]
    return []


def _find_first_value(obj, candidate_keys):
    if isinstance(obj, dict):
        for key in candidate_keys:
            if key in obj and obj[key] is not None:
                return obj[key]
        for value in obj.values():
            found = _find_first_value(value, candidate_keys)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_first_value(item, candidate_keys)
            if found is not None:
                return found
    return None


def _openmetrics_payload(registry):
    payload = generate_latest(registry)
    if not payload.rstrip().endswith(b"# EOF"):
        payload = payload.rstrip() + b"\n# EOF\n"
    return payload


def _latest_numeric_from_payload(payload):
    best_ts = -1
    best_val = None

    def visit(obj):
        nonlocal best_ts, best_val

        if isinstance(obj, list):
            for item in obj:
                visit(item)
            return

        if not isinstance(obj, dict):
            return

        val = _first_present(obj, ["data", "value", "metricValue", "y", "avg", "average", "sum"])
        if val is not None:
            ts = _to_int(_first_present(obj, ["timestampMsecs", "timestampUsecs", "timestampSecs", "timestamp", "time"]), 0)
            fval = _to_float(val, None)
            if fval is not None and ts >= best_ts:
                best_ts = ts
                best_val = fval

        for key in ["dataPointVec", "dataPoints", "points", "stats", "series", "samples", "items", "data"]:
            if key in obj:
                visit(obj[key])

    visit(payload)

    if best_val is not None:
        return best_val

    if isinstance(payload, dict):
        val = _first_present(payload, ["data", "value", "metricValue", "latestValue", "avg", "average", "sum"])
        if val is not None:
            return _to_float(val, 0.0)

    return 0.0


def node_numeric_value(node, keys, default=0.0):
    return _to_float(_find_first_value(node, keys), default)


def node_list_count(node, keys, default=0.0):
    found = _find_first_value(node, keys)
    if isinstance(found, list):
        return float(len(found))
    return default


def node_key(node):
    return _label_safe(_first_present(node, ["id", "nodeId", "name", "nodeName"]))


def merge_node_stats_detail(base_node, detail):
    if not isinstance(base_node, dict):
        base_node = {}
    if not isinstance(detail, dict):
        return base_node

    merged = dict(base_node)

    for key, value in detail.items():
        if key not in merged or merged[key] in [None, "", "unknown", 0, 0.0]:
            merged[key] = value
        else:
            merged[f"detail_{key}"] = value

    return merged


def node_numeric_value(node, keys, default=0.0):
    return _to_float(_find_first_value(node, keys), default)


def node_bool_value(node, keys, default=0.0):
    value = _find_first_value(node, keys)
    if value is True:
        return 1.0
    if value is False:
        return 0.0
    if isinstance(value, str):
        if value.lower() in ["true", "yes", "1", "enabled"]:
            return 1.0
        if value.lower() in ["false", "no", "0", "disabled"]:
            return 0.0
    return default


def node_health_value(node):
    raw_status = _find_first_value(
        node,
        [
            "status", "state", "health", "nodeHealth", "healthStatus",
            "nodeStatus", "statusDescription", "statusDesc"
        ],
    )
    status = _label_safe(raw_status).lower()

    healthy_values = {
        "healthy", "online", "ready", "ok", "good", "up", "connected", "green",
        "khealthy", "konline", "kready", "kok", "available", "kavailable"
    }
    degraded_values = {
        "degraded", "warning", "yellow", "kdegraded", "kwarning"
    }
    unhealthy_values = {
        "offline", "down", "error", "failed", "critical", "red", "disconnected",
        "koffline", "kdown", "kerror", "kfailed", "kcritical", "unavailable", "kunavailable"
    }

    if status in healthy_values:
        return "healthy", 1
    if status in degraded_values:
        return "degraded", 0
    if status in unhealthy_values:
        return status, 0

    is_online = _find_first_value(node, ["isOnline", "online"])
    if is_online is True:
        return "online", 1
    if is_online is False:
        return "offline", 0

    is_healthy = _find_first_value(node, ["isHealthy", "healthy"])
    if is_healthy is True:
        return "healthy", 1
    if is_healthy is False:
        return "unhealthy", 0

    # Practical fallback: if /nodes returns it and no health field exists, treat as present/online.
    return "online", 1


class CohesityClient:
    def __init__(self, vip, username, domain, password):
        self.vip = vip
        self.username = username
        self.domain = domain
        self.password = password
        self.base_url = f"https://{vip}"
        self.session = requests.Session()
        self.session.verify = False
        self.token = None
        self.lock = threading.Lock()

    def authenticate(self, force=False):
        with self.lock:
            if self.token and not force:
                return True

            if not self.password:
                warn("no password provided")
                return False

            url = f"{self.base_url}/irisservices/api/v1/public/accessTokens"
            payload = {
                "domain": self.domain,
                "username": self.username,
                "password": self.password,
            }

            try:
                response = self.session.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                    timeout=30,
                )
                log(f"auth status_code={response.status_code}")

                if not response.ok:
                    warn(f"auth failed status={response.status_code} body={response.text[:500]}")
                    return False

                body = response.json()
                token = body.get("accessToken")
                if not token:
                    warn(f"auth response missing accessToken: {body}")
                    return False

                self.token = token
                self.session.headers.update(
                    {
                        "Authorization": f"Bearer {self.token}",
                        "Accept": "application/json",
                    }
                )
                log("auth success, bearer token installed")
                return True

            except Exception as e:
                err(f"auth exception: {e}")
                traceback.print_exc()
                return False

    def get(self, path, params=None, retry_auth=True):
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            if not path.startswith("/"):
                path = "/" + path
            url = self.base_url + path

        if not self.authenticate():
            return None

        try:
            response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            log(f"GET status={response.status_code} url={response.url}")

            if response.status_code == 401 and retry_auth:
                warn(f"401 on {url}, refreshing token")
                if self.authenticate(force=True):
                    return self.get(path, params=params, retry_auth=False)
                return None

            if not response.ok:
                warn(f"GET failed {url} status={response.status_code} body={response.text[:500]}")
                return None

            if not response.text.strip():
                return None

            return response.json()
        except Exception as e:
            warn(f"GET exception {url}: {e}")
            traceback.print_exc()
            return None


def try_api_get(client, candidates, metric_name="unknown"):
    for candidate in candidates:
        if isinstance(candidate, tuple):
            path = candidate[0]
            params = dict(candidate[1])
        else:
            path = candidate
            params = None

        payload = client.get(path, params=params)
        if payload is not None:
            if isinstance(payload, list):
                log(f"API OK {path} -> list[{len(payload)}] for {metric_name}")
            elif isinstance(payload, dict):
                log(f"API OK {path} -> dict keys={list(payload.keys())[:10]} for {metric_name}")
            else:
                log(f"API OK {path} -> {type(payload)} for {metric_name}")
            return payload

    log(f"API EMPTY for {metric_name}")
    return None


def get_v2_cluster(client):
    payload = try_api_get(
        client,
        [
            ("/v2/clusters", {"fetchStats": "true", "fetchTimeSeriesSchema": "true"}),
            ("/irisservices/api/v2/clusters", {"fetchStats": "true", "fetchTimeSeriesSchema": "true"}),
            "/v2/clusters",
            "/irisservices/api/v2/clusters",
            "/irisservices/api/v1/public/cluster",
            "/cluster",
        ],
        metric_name="cluster_identity",
    )

    if isinstance(payload, list) and payload:
        return payload[0]
    if isinstance(payload, dict):
        for key in ["clusters", "items", "data", "entities"]:
            if isinstance(payload.get(key), list) and payload[key]:
                return payload[key][0]
        return payload

    return {}


def get_cluster_identity_from_any(cluster, nodes, alerts, jobs):
    summary = {
        "name": "unknown",
        "id": "unknown",
        "softwareVersion": "unknown",
        "nodeCount": 0,
    }

    if isinstance(cluster, dict):
        summary["name"] = _label_safe(_first_present(cluster, [
            "name", "clusterName", "cluster_name", "displayName"
        ], "unknown"))
        summary["id"] = _label_safe(_first_present(cluster, [
            "id", "clusterId", "cluster_id"
        ], "unknown"))
        summary["softwareVersion"] = _label_safe(_first_present(cluster, [
            "clusterSoftwareVersion", "softwareVersion", "version", "buildVersion"
        ], "unknown"))
        summary["nodeCount"] = _to_int(_first_present(cluster, [
            "nodeCount", "numNodes", "numberOfNodes"
        ], 0), 0)

    # Fall back to any payload that might carry cluster labels.
    for collection in [nodes, alerts, jobs]:
        if not collection:
            continue
        sample = collection[0]
        if not isinstance(sample, dict):
            continue
        if summary["name"] == "unknown":
            summary["name"] = _label_safe(_first_present(sample, ["clusterName", "cluster", "cluster_name"], "unknown"))
        if summary["id"] == "unknown":
            summary["id"] = _label_safe(_first_present(sample, ["clusterId", "cluster_id"], "unknown"))
        if summary["softwareVersion"] == "unknown":
            summary["softwareVersion"] = _label_safe(_first_present(sample, ["softwareVersion", "clusterSoftwareVersion", "version"], "unknown"))

    if summary["nodeCount"] == 0 and nodes:
        summary["nodeCount"] = len(nodes)

    return summary


def get_cluster_stat_v2_or_v1(client, metric_name, cluster_summary=None, default=0.0):
    # Disabled: cluster capacity/perf stats are read directly from /v2/clusters?fetchStats=true.
    return default


def get_first_cluster_stat(client, metric_names, cluster_summary=None, default=0.0):
    # Disabled: cluster capacity/perf stats are read directly from /v2/clusters?fetchStats=true.
    return default, ""


def get_nodes(client):
    """
    Confirmed working batched node endpoint.

    With fetchStats=true, Cohesity populates:
      node.stats.usagePerfStats.physicalCapacityBytes
      node.stats.usagePerfStats.systemCapacityBytes
      node.stats.usagePerfStats.totalPhysicalUsageBytes
      node.stats.usagePerfStats.totalPhysicalRawUsageBytes
      node.stats.usagePerfStats.systemUsageBytes
      node.stats.usagePerfStats.numBytesRead
      node.stats.usagePerfStats.numBytesWritten
      node.stats.usagePerfStats.readIos
      node.stats.usagePerfStats.writeIos
      node.stats.usagePerfStats.readLatencyMsecs
      node.stats.usagePerfStats.writeLatencyMsecs
    """
    endpoints = [
        ("/irisservices/api/v1/public/nodes", {"fetchStats": "true"}),
        "/irisservices/api/v1/public/nodes",
        "/irisservices/api/v2/nodes",
        "/irisservices/api/v2/cluster/nodes",
        "/nodes",
    ]

    return _walk_list(
        try_api_get(
            client,
            endpoints,
            metric_name="nodes",
        )
    )


def get_alerts(client):
    return _walk_list(
        try_api_get(
            client,
            [
                "/irisservices/api/v2/alerts",
                "/irisservices/api/v1/public/alerts",
                "/alerts",
            ],
            metric_name="alerts",
        )
    )


def get_jobs(client):
    return _walk_list(
        try_api_get(
            client,
            [
                "/irisservices/api/v2/data-protect/protection-groups",
                "/irisservices/api/v2/protection-groups",
                "/irisservices/api/v1/public/protectionJobs",
                "/protectionJobs",
            ],
            metric_name="jobs",
        )
    )


def get_sources(client):
    return _walk_list(
        try_api_get(
            client,
            [
                "/irisservices/api/v2/data-protect/sources",
                "/irisservices/api/v2/protection-sources",
                "/irisservices/api/v1/public/protectionSources",
                "/protectionSources",
            ],
            metric_name="sources",
        )
    )


def get_runs_for_job(client, job_id):
    if not job_id or job_id == "unknown":
        return []
    payload = try_api_get(
        client,
        [
            (f"/irisservices/api/v2/data-protect/protection-groups/{job_id}/runs", {"numRuns": 20}),
            ("/irisservices/api/v1/public/protectionRuns", {"jobId": job_id, "numRuns": 20}),
            ("/protectionRuns", {"jobId": job_id, "numRuns": 20}),
        ],
        metric_name=f"job_runs_{job_id}",
    )
    return _walk_list(payload)


def get_cluster_summary(client, nodes=None, alerts=None, jobs=None):
    nodes = nodes or []
    alerts = alerts or []
    jobs = jobs or []

    cluster = get_v2_cluster(client)

    stats = cluster.get("stats", {}) if isinstance(cluster.get("stats"), dict) else {}
    usage_perf = stats.get("usagePerfStats", {}) if isinstance(stats.get("usagePerfStats"), dict) else {}
    local_usage_perf = stats.get("localUsagePerfStats", {}) if isinstance(stats.get("localUsagePerfStats"), dict) else {}
    logical_stats = stats.get("logicalStats", {}) if isinstance(stats.get("logicalStats"), dict) else {}
    data_usage = stats.get("dataUsageStats", {}) if isinstance(stats.get("dataUsageStats"), dict) else {}

    identity = get_cluster_identity_from_any(cluster, nodes, alerts, jobs)

    usable_bytes = _to_float(_first_present(usage_perf, ["physicalCapacityBytes"], 0.0), 0.0)
    if usable_bytes == 0.0:
        usable_bytes = _to_float(_first_present(local_usage_perf, ["physicalCapacityBytes"], 0.0), 0.0)

    used_bytes = _to_float(_first_present(usage_perf, ["totalPhysicalUsageBytes"], 0.0), 0.0)
    if used_bytes == 0.0:
        used_bytes = _to_float(_first_present(data_usage, ["localTotalPhysicalUsageBytes", "dataProtectPhysicalUsageBytes"], 0.0), 0.0)
    if used_bytes == 0.0:
        used_bytes = _to_float(_first_present(local_usage_perf, ["totalPhysicalUsageBytes"], 0.0), 0.0)

    logical_bytes = _to_float(_first_present(logical_stats, ["totalLogicalUsageBytes"], 0.0), 0.0)
    if logical_bytes == 0.0:
        logical_bytes = _to_float(_first_present(data_usage, ["totalLogicalUsageBytes", "dataProtectLogicalUsageBytes"], 0.0), 0.0)

    data_reduction = _to_float(_first_present(stats, ["dataReductionRatio"], 0.0), 0.0)
    if data_reduction == 0.0 and logical_bytes > 0.0 and used_bytes > 0.0:
        data_reduction = logical_bytes / used_bytes

    free_bytes = max(usable_bytes - used_bytes, 0.0) if usable_bytes > 0.0 and used_bytes > 0.0 else 0.0
    storage_efficiency = logical_bytes / used_bytes if logical_bytes > 0.0 and used_bytes > 0.0 else data_reduction

    summary = {
        "name": identity["name"],
        "id": identity["id"],
        "softwareVersion": identity["softwareVersion"],
        "nodeCount": identity["nodeCount"],

        "usableBytes": usable_bytes,
        "usedBytes": used_bytes,
        "physicalUsedBytes": used_bytes,
        "freeBytes": free_bytes,
        "logicalBytes": logical_bytes,
        "dataReduction": data_reduction,
        "storageEfficiency": storage_efficiency,

        "cpuUtilizationPercent": 0.0,
        "bytesBackedUp": _to_float(_first_present(usage_perf, ["dataInBytes"], 0.0), 0.0),
        "writeThroughputBytesPerSec": _to_float(_first_present(usage_perf, ["numBytesWritten"], 0.0), 0.0),
        "readThroughputBytesPerSec": _to_float(_first_present(usage_perf, ["numBytesRead"], 0.0), 0.0),
        "morphedGarbageBytes": 0.0,

        "dataInBytes": _to_float(_first_present(usage_perf, ["dataInBytes"], 0.0), 0.0),
        "dataInAfterReductionBytes": _to_float(_first_present(usage_perf, ["dataInBytesAfterReduction"], 0.0), 0.0),
        "dataInAfterDedupBytes": _to_float(_first_present(data_usage, ["dataInBytesAfterDedup"], 0.0), 0.0),
        "dataWrittenBytes": _to_float(_first_present(data_usage, ["dataWrittenBytes", "localDataWrittenBytes"], 0.0), 0.0),
        "numBytesRead": _to_float(_first_present(usage_perf, ["numBytesRead"], 0.0), 0.0),
        "numBytesWritten": _to_float(_first_present(usage_perf, ["numBytesWritten"], 0.0), 0.0),
        "readIos": _to_float(_first_present(usage_perf, ["readIos"], 0.0), 0.0),
        "writeIos": _to_float(_first_present(usage_perf, ["writeIos"], 0.0), 0.0),
        "readLatencyMsecs": _to_float(_first_present(usage_perf, ["readLatencyMsecs"], 0.0), 0.0),
        "writeLatencyMsecs": _to_float(_first_present(usage_perf, ["writeLatencyMsecs"], 0.0), 0.0),
        "systemCapacityBytes": _to_float(_first_present(usage_perf, ["systemCapacityBytes"], 0.0), 0.0),
        "systemUsageBytes": _to_float(_first_present(usage_perf, ["systemUsageBytes"], 0.0), 0.0),
        "totalPhysicalRawUsageBytes": _to_float(_first_present(usage_perf, ["totalPhysicalRawUsageBytes"], 0.0), 0.0),
        "minUsablePhysicalCapacityBytes": _to_float(_first_present(local_usage_perf, ["minUsablePhysicalCapacityBytes"], 0.0), 0.0),
        "localResiliencyImpactBytes": _to_float(_first_present(data_usage, ["localTierResiliencyImpactBytes"], 0.0), 0.0),

        # Hardware / topology summary from /v2/clusters.
        "chassisCount": _to_float(_first_present(cluster, ["chassisCount"], 0.0), 0.0),
        "assignedRacksCount": _to_float(_first_present(cluster, ["assignedRacksCount"], 0.0), 0.0),
        "diskCountPcieSsd": 0.0,
        "diskCountSataHdd": 0.0,
    }

    for disk_tier in cluster.get("diskCountByTier", []) if isinstance(cluster.get("diskCountByTier"), list) else []:
        tier = _label_safe(disk_tier.get("storageTier")).lower()
        count = _to_float(disk_tier.get("diskCount"), 0.0)
        if "pcie" in tier or "ssd" in tier:
            summary["diskCountPcieSsd"] = summary.get("diskCountPcieSsd", 0.0) + count
        elif "sata" in tier or "hdd" in tier:
            summary["diskCountSataHdd"] = summary.get("diskCountSataHdd", 0.0) + count

    log(
        "cluster summary "
        f"name={summary['name']} id={summary['id']} version={summary['softwareVersion']} "
        f"nodes={summary['nodeCount']} usable={summary['usableBytes']} "
        f"used={summary['usedBytes']} free={summary['freeBytes']} "
        f"logical={summary['logicalBytes']} reduction={summary['dataReduction']}"
    )

    return summary


def job_name(job):
    return _label_safe(_first_present(job, ["name", "jobName", "protectionGroupName"]))


def job_id(job):
    return _label_safe(_first_present(job, ["id", "jobId", "protectionGroupId"]))


def job_environment(job):
    return _label_safe(_first_present(job, ["environment", "sourceEnvironment", "sourceType"]))


def job_is_paused(job):
    return 1 if bool(_first_present(job, ["isPaused", "paused"], False)) else 0


def job_is_active(job):
    raw = _first_present(job, ["isActive", "active"])
    if raw is None:
        return 1
    return 1 if bool(raw) else 0


def source_name(source):
    return _label_safe(_first_present(source, ["name", "sourceName", "displayName"]))


def source_id(source):
    return _label_safe(_first_present(source, ["id", "sourceId"]))


def source_environment(source):
    return _label_safe(_first_present(source, ["environment", "sourceEnvironment", "sourceType"]))


def source_protected(source):
    raw = _first_present(source, ["isProtected", "protected"])
    if raw is None:
        # In some APIs, sources endpoint only returns registered sources, not protection state.
        return 0
    return 1 if bool(raw) else 0


class RenderedMetricsCache:
    def __init__(self):
        self.lock = threading.Lock()
        self.payload = b"# exporter not initialized yet\n# EOF\n"

    def set_payload(self, payload):
        with self.lock:
            self.payload = payload

    def get_payload(self):
        with self.lock:
            return self.payload


class _SingleMetricCollector:
    def __init__(self, metric):
        self.metric = metric

    def collect(self):
        yield self.metric


class MetricsBuilder:
    def render(self, data):
        registry = CollectorRegistry()

        GCCollector(registry=registry)
        PlatformCollector(registry=registry)
        ProcessCollector(registry=registry)

        metrics = []

        def add_metric(metric_name, description, value, labels=None, label_values=None):
            labels = labels or []
            label_values = label_values or []
            gm = GaugeMetricFamily(metric_name, description, labels=labels)
            gm.add_metric(label_values, float(value))
            metrics.append(gm)

        add_metric("cohesity_exporter_auth_success", "1 if auth worked", data.get("auth_ok", 0))
        add_metric("cohesity_exporter_last_refresh_success", "1 if last refresh worked", data.get("last_refresh_success", 0))
        add_metric("cohesity_exporter_last_refresh_duration_seconds", "Duration of last background refresh", data.get("last_refresh_duration_seconds", 0.0))
        add_metric("cohesity_exporter_last_refresh_timestamp_seconds", "Unix timestamp of last refresh attempt", data.get("last_refresh_timestamp_seconds", 0.0))
        add_metric("cohesity_exporter_errors_total", "Error count seen during the last refresh cycle", data.get("errors", 0))

        if data.get("auth_ok", 0):
            cluster = data.get("cluster", {})
            common_labels = ["cluster", "cluster_id", "software_version"]
            common = [
                _label_safe(cluster.get("name", "unknown")),
                _label_safe(cluster.get("id", "unknown")),
                _label_safe(cluster.get("softwareVersion", "unknown")),
            ]

            for name, desc, val in [
                ("cohesity_cluster_node_count", "Number of nodes in the cluster", cluster.get("nodeCount", 0)),
                ("cohesity_cluster_usable_bytes", "Usable/total cluster capacity in bytes", cluster.get("usableBytes", 0.0)),
                ("cohesity_cluster_used_bytes", "Physical used capacity in bytes", cluster.get("usedBytes", 0.0)),
                ("cohesity_cluster_physical_used_bytes", "Physical used capacity in bytes", cluster.get("physicalUsedBytes", 0.0)),
                ("cohesity_cluster_free_bytes", "Free capacity in bytes", cluster.get("freeBytes", 0.0)),
                ("cohesity_cluster_logical_bytes", "Logical protected data in bytes", cluster.get("logicalBytes", 0.0)),
                ("cohesity_cluster_storage_efficiency_ratio", "Logical to physical efficiency ratio", cluster.get("storageEfficiency", 0.0)),
                ("cohesity_cluster_data_reduction_ratio", "Data reduction ratio", cluster.get("dataReduction", 0.0)),
                ("cohesity_cluster_cpu_utilization_percent", "Cluster CPU utilization percent", cluster.get("cpuUtilizationPercent", 0.0)),
                ("cohesity_cluster_bytes_backed_up", "Cluster bytes backed up / ingested", cluster.get("bytesBackedUp", 0.0)),
                ("cohesity_cluster_bytes_written_snapshot", "Cluster bytes written snapshot from Cohesity API", cluster.get("writeThroughputBytesPerSec", 0.0)),
                ("cohesity_cluster_bytes_read_snapshot", "Cluster bytes read snapshot from Cohesity API", cluster.get("readThroughputBytesPerSec", 0.0)),
                ("cohesity_cluster_morphed_garbage_bytes", "Morphed garbage bytes", cluster.get("morphedGarbageBytes", 0.0)),
                ("cohesity_cluster_data_in_bytes", "Logical data in bytes", cluster.get("dataInBytes", 0.0)),
                ("cohesity_cluster_data_in_after_reduction_bytes", "Data in bytes after reduction", cluster.get("dataInAfterReductionBytes", 0.0)),
                ("cohesity_cluster_data_in_after_dedup_bytes", "Data in bytes after deduplication", cluster.get("dataInAfterDedupBytes", 0.0)),
                ("cohesity_cluster_data_written_bytes", "Data written bytes", cluster.get("dataWrittenBytes", 0.0)),
                ("cohesity_cluster_num_bytes_read", "Bytes read", cluster.get("numBytesRead", 0.0)),
                ("cohesity_cluster_num_bytes_written", "Bytes written", cluster.get("numBytesWritten", 0.0)),
                ("cohesity_cluster_read_ios", "Read IO count", cluster.get("readIos", 0.0)),
                ("cohesity_cluster_write_ios", "Write IO count", cluster.get("writeIos", 0.0)),
                ("cohesity_cluster_read_latency_msecs", "Read latency in milliseconds", cluster.get("readLatencyMsecs", 0.0)),
                ("cohesity_cluster_write_latency_msecs", "Write latency in milliseconds", cluster.get("writeLatencyMsecs", 0.0)),
                ("cohesity_cluster_system_capacity_bytes", "System capacity bytes", cluster.get("systemCapacityBytes", 0.0)),
                ("cohesity_cluster_system_usage_bytes", "System usage bytes", cluster.get("systemUsageBytes", 0.0)),
                ("cohesity_cluster_total_physical_raw_usage_bytes", "Total physical raw usage bytes", cluster.get("totalPhysicalRawUsageBytes", 0.0)),
                ("cohesity_cluster_min_usable_physical_capacity_bytes", "Minimum usable physical capacity bytes", cluster.get("minUsablePhysicalCapacityBytes", 0.0)),
                ("cohesity_cluster_local_resiliency_impact_bytes", "Local resiliency impact bytes", cluster.get("localResiliencyImpactBytes", 0.0)),
                ("cohesity_cluster_chassis_count", "Cluster chassis count", cluster.get("chassisCount", 0.0)),
                ("cohesity_cluster_assigned_racks_count", "Assigned racks count", cluster.get("assignedRacksCount", 0.0)),
                ("cohesity_cluster_pcie_ssd_disk_count", "PCIe SSD disk count", cluster.get("diskCountPcieSsd", 0.0)),
                ("cohesity_cluster_sata_hdd_disk_count", "SATA HDD disk count", cluster.get("diskCountSataHdd", 0.0)),
            ]:
                add_metric(name, desc, val, common_labels, common)

            alerts = data.get("alerts", [])
            add_metric("cohesity_alerts_total", "Total alerts returned by the API", len(alerts), common_labels, common)

            sev_counts = {}
            status_counts = {}
            for alert in alerts:
                severity = _label_safe(_first_present(alert, ["severity", "alertSeverity"]))
                status = _label_safe(_first_present(alert, ["status", "alertState", "state"]))
                sev_counts[severity] = sev_counts.get(severity, 0) + 1
                status_counts[status] = status_counts.get(status, 0) + 1

            gm = GaugeMetricFamily("cohesity_alerts_by_severity", "Alerts by severity", labels=common_labels + ["severity"])
            for severity, count in sev_counts.items():
                gm.add_metric(common + [severity], float(count))
            metrics.append(gm)

            gm = GaugeMetricFamily("cohesity_alerts_by_status", "Alerts by status", labels=common_labels + ["status"])
            for status, count in status_counts.items():
                gm.add_metric(common + [status], float(count))
            metrics.append(gm)

            nodes = data.get("nodes", [])
            add_metric("cohesity_nodes_total", "Total nodes", len(nodes), common_labels, common)

            gm = GaugeMetricFamily(
                "cohesity_node_health",
                "Node health state (1 healthy, 0 unhealthy/unknown)",
                labels=common_labels + ["node", "node_id", "status"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                status, value = node_health_value(node)
                gm.add_metric(common + [node_name, node_id, status], float(value))
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_disk_count",
                "Node disk count if exposed by the node API",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                disk_count = node_numeric_value(node, ["diskCount", "numDisks", "numberOfDisks"], 0.0)
                if disk_count == 0.0:
                    disk_count = node_list_count(node, ["disks", "diskInfo", "diskInfos"], 0.0)
                gm.add_metric(common + [node_name, node_id], disk_count)
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_disk_failed_count",
                "Node failed disk count if exposed by the node API",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                failed = node_numeric_value(node, ["failedDiskCount", "numFailedDisks", "failedDisks", "diskFailureCount"], 0.0)
                gm.add_metric(common + [node_name, node_id], failed)
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_max_physical_capacity_bytes",
                "Node maximum physical capacity in bytes from v1 public node inventory",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                gm.add_metric(common + [node_name, node_id], node_numeric_value(node, ["maxPhysicalCapacityBytes"], 0.0))
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_slot_number",
                "Node slot number from v1 public node inventory",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                gm.add_metric(common + [node_name, node_id], node_numeric_value(node, ["slotNumber"], 0.0))
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_upgrade_in_progress",
                "1 if node upgrade is in progress",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                gm.add_metric(common + [node_name, node_id], node_bool_value(node, ["upgradeInProgress"], 0.0))
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_marked_for_removal",
                "1 if node is marked for removal",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                gm.add_metric(common + [node_name, node_id], node_bool_value(node, ["isMarkedForRemoval"], 0.0))
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_app_node",
                "1 if node is an app node",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                gm.add_metric(common + [node_name, node_id], node_bool_value(node, ["isAppNode"], 0.0))
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_pcie_ssd_disk_count",
                "Node PCIe SSD disk count from v1 public node inventory",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                count = 0.0
                for disk_tier in node.get("diskCountByTier", []) if isinstance(node.get("diskCountByTier"), list) else []:
                    tier = _label_safe(disk_tier.get("storageTier")).lower()
                    if "pcie" in tier or "ssd" in tier:
                        count += _to_float(disk_tier.get("diskCount"), 0.0)
                gm.add_metric(common + [node_name, node_id], count)
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_sata_hdd_disk_count",
                "Node SATA HDD disk count from v1 public node inventory",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                count = 0.0
                for disk_tier in node.get("diskCountByTier", []) if isinstance(node.get("diskCountByTier"), list) else []:
                    tier = _label_safe(disk_tier.get("storageTier")).lower()
                    if "sata" in tier or "hdd" in tier:
                        count += _to_float(disk_tier.get("diskCount"), 0.0)
                gm.add_metric(common + [node_name, node_id], count)
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_max_physical_capacity_bytes",
                "Node maximum physical capacity in bytes from node inventory",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                gm.add_metric(common + [node_name, node_id], node_numeric_value(node, ["maxPhysicalCapacityBytes"], 0.0))
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_upgrade_in_progress",
                "1 if node upgrade is in progress",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                gm.add_metric(common + [node_name, node_id], node_bool_value(node, ["upgradeInProgress"], 0.0))
            metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_marked_for_removal",
                "1 if node is marked for removal",
                labels=common_labels + ["node", "node_id"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                gm.add_metric(common + [node_name, node_id], node_bool_value(node, ["isMarkedForRemoval"], 0.0))
            metrics.append(gm)


            # Node-level stats from /irisservices/api/v1/public/nodes?fetchStats=true.
            # These are nested under node.stats.usagePerfStats in the Cohesity response.
            node_stat_specs = [
                (
                    "cohesity_node_physical_capacity_bytes",
                    "Node physical capacity in bytes from stats.usagePerfStats",
                    "physicalCapacityBytes",
                ),
                (
                    "cohesity_node_system_capacity_bytes",
                    "Node system capacity in bytes from stats.usagePerfStats",
                    "systemCapacityBytes",
                ),
                (
                    "cohesity_node_total_physical_usage_bytes",
                    "Node total physical usage bytes from stats.usagePerfStats",
                    "totalPhysicalUsageBytes",
                ),
                (
                    "cohesity_node_total_physical_raw_usage_bytes",
                    "Node total physical raw usage bytes from stats.usagePerfStats",
                    "totalPhysicalRawUsageBytes",
                ),
                (
                    "cohesity_node_system_usage_bytes",
                    "Node system usage bytes from stats.usagePerfStats",
                    "systemUsageBytes",
                ),
                (
                    "cohesity_node_num_bytes_read",
                    "Node bytes read snapshot from stats.usagePerfStats",
                    "numBytesRead",
                ),
                (
                    "cohesity_node_num_bytes_written",
                    "Node bytes written snapshot from stats.usagePerfStats",
                    "numBytesWritten",
                ),
                (
                    "cohesity_node_read_ios",
                    "Node read IO count from stats.usagePerfStats",
                    "readIos",
                ),
                (
                    "cohesity_node_write_ios",
                    "Node write IO count from stats.usagePerfStats",
                    "writeIos",
                ),
                (
                    "cohesity_node_read_latency_msecs",
                    "Node read latency in milliseconds from stats.usagePerfStats",
                    "readLatencyMsecs",
                ),
                (
                    "cohesity_node_write_latency_msecs",
                    "Node write latency in milliseconds from stats.usagePerfStats",
                    "writeLatencyMsecs",
                ),
            ]

            for metric_name, metric_help, field_name in node_stat_specs:
                gm = GaugeMetricFamily(
                    metric_name,
                    metric_help,
                    labels=common_labels + ["node", "node_id"],
                )
                for node in nodes:
                    node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                    node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                    value = 0.0
                    if isinstance(node, dict):
                        stats = node.get("stats", {})
                        if isinstance(stats, dict):
                            usage_perf = stats.get("usagePerfStats", {})
                            if isinstance(usage_perf, dict):
                                value = _to_float(usage_perf.get(field_name), 0.0)
                        if value == 0.0:
                            value = node_numeric_value(node, [field_name], 0.0)
                    gm.add_metric(common + [node_name, node_id], value)
                metrics.append(gm)

            gm = GaugeMetricFamily(
                "cohesity_node_metadata",
                "Node hardware metadata as labels with value 1",
                labels=common_labels + ["node", "node_id", "ip", "host_name", "product_model", "hardware_model", "node_type", "partition", "node_serial", "chassis_name", "chassis_serial", "chassis_id", "vendor"],
            )
            for node in nodes:
                node_name = _label_safe(_first_present(node, ["name", "nodeName", "id"]))
                node_id = _label_safe(_first_present(node, ["id", "nodeId"]))
                ip = _label_safe(_find_first_value(node, ["ip", "ipAddress", "nodeIp", "nodeIpAddress"]))
                host_name = _label_safe(_find_first_value(node, ["hostName", "hostname", "nodeHostname"]))
                product_model = _label_safe(_find_first_value(node, ["productModel"]))
                hardware_model = _label_safe(_find_first_value(node, ["hardwareModel", "model"]))
                node_type = _label_safe(_find_first_value(node, ["nodeType"]))
                partition = _label_safe(_find_first_value(node, ["clusterPartitionName"]))
                node_serial = _label_safe(_find_first_value(node, ["cohesityNodeSerial", "nodeSerial"]))
                chassis_name = _label_safe(_find_first_value(node, ["chassisName"]))
                chassis_serial = _label_safe(_find_first_value(node, ["chassisSerial"]))
                chassis_id = _label_safe(_find_first_value(node, ["chassisId"]))
                vendor = _label_safe(_find_first_value(node, ["vendor", "hardwareVendor", "manufacturer"]))
                gm.add_metric(common + [node_name, node_id, ip, host_name, product_model, hardware_model, node_type, partition, node_serial, chassis_name, chassis_serial, chassis_id, vendor], 1.0)
            metrics.append(gm)

            jobs = data.get("jobs", [])
            add_metric("cohesity_jobs_total", "Total protection jobs", len(jobs), common_labels, common)

            gm = GaugeMetricFamily(
                "cohesity_job_state",
                "Job active and pause state",
                labels=common_labels + ["job", "job_id", "environment", "state"],
            )
            for job in jobs:
                jn = job_name(job)
                jid = job_id(job)
                env = job_environment(job)
                gm.add_metric(common + [jn, jid, env, "active"], float(job_is_active(job)))
                gm.add_metric(common + [jn, jid, env, "paused"], float(job_is_paused(job)))
            metrics.append(gm)

            sources = data.get("sources", [])
            add_metric("cohesity_sources_total", "Total sources returned by the API", len(sources), common_labels, common)

            gm = GaugeMetricFamily(
                "cohesity_source_protected",
                "Whether a source is protected",
                labels=common_labels + ["source", "source_id", "environment"],
            )
            seen_source_samples = set()
            for idx, source in enumerate(sources):
                sn = source_name(source)
                sid = source_id(source)
                env = source_environment(source)
                if sn == "unknown" and sid == "unknown":
                    sid = str(idx)
                key = (sn, sid, env)
                if key in seen_source_samples:
                    continue
                seen_source_samples.add(key)
                gm.add_metric(common + [sn, sid, env], float(source_protected(source)))
            metrics.append(gm)

            if INCLUDE_JOB_RUNS:
                job_runs = data.get("job_runs", {})

                gm_status = GaugeMetricFamily(
                    "cohesity_job_last_run_status",
                    "Last run success state per job (1 success, 0 otherwise)",
                    labels=common_labels + ["job", "job_id", "environment"],
                )
                gm_counts = GaugeMetricFamily(
                    "cohesity_job_runs_total",
                    "Number of recent runs returned per job/status",
                    labels=common_labels + ["job", "job_id", "environment", "status"],
                )
                gm_time = GaugeMetricFamily(
                    "cohesity_job_last_run_timestamp_usecs",
                    "Timestamp of last observed run",
                    labels=common_labels + ["job", "job_id", "environment"],
                )

                for job in jobs:
                    jn = job_name(job)
                    jid = job_id(job)
                    env = job_environment(job)
                    run_info = job_runs.get(str(jid), {})

                    gm_status.add_metric(common + [jn, jid, env], float(run_info.get("last_status_success", 0)))
                    gm_time.add_metric(common + [jn, jid, env], float(run_info.get("last_run_timestamp_usecs", 0)))

                    for status, count in run_info.get("counts", {}).items():
                        gm_counts.add_metric(common + [jn, jid, env, status], float(count))

                metrics.extend([gm_status, gm_counts, gm_time])

        for metric in metrics:
            registry.register(_SingleMetricCollector(metric))

        return _openmetrics_payload(registry)


class BackgroundRefresher(threading.Thread):
    def __init__(self, client, cache):
        super().__init__(daemon=True)
        self.client = client
        self.cache = cache
        self.builder = MetricsBuilder()

        self.state_lock = threading.Lock()
        self.state = {
            "auth_ok": 0,
            "cluster": {},
            "alerts": [],
            "nodes": [],
            "jobs": [],
            "sources": [],
            "job_runs": {},
            "errors": 0,
            "last_refresh_success": 0,
            "last_refresh_duration_seconds": 0.0,
            "last_refresh_timestamp_seconds": 0.0,
        }

        # Last refresh times per API family. Force all families to refresh at startup.
        self.last_refresh = {
            "cluster": 0.0,
            "alerts": 0.0,
            "jobs": 0.0,
            "sources": 0.0,
            "job_runs": 0.0,
            "node_stats": 0.0,
        }

    def collect_job_run_info(self, jobs):
        results = {}

        def worker(job):
            jid = job_id(job)
            runs = get_runs_for_job(self.client, jid)
            counts = {}
            latest_run = None
            latest_ts = -1

            for run in runs:
                status = _label_safe(_first_present(run, ["status", "runStatus"]))
                counts[status] = counts.get(status, 0) + 1
                ts = _to_int(_first_present(run, ["startTimeUsecs", "startTime", "runStartTimeUsecs"]), 0)
                if ts > latest_ts:
                    latest_ts = ts
                    latest_run = run

            success_value = 0
            if latest_run is not None:
                last_status = _label_safe(_first_present(latest_run, ["status", "runStatus"]))
                success_value = 1 if last_status.lower() in ["success", "succeeded", "ksuccess"] else 0

            return str(jid), {
                "counts": counts,
                "last_status_success": success_value,
                "last_run_timestamp_usecs": latest_ts if latest_ts > 0 else 0,
            }

        with ThreadPoolExecutor(max_workers=RUN_WORKERS) as pool:
            futures = [pool.submit(worker, job) for job in jobs]
            for future in as_completed(futures):
                try:
                    jid, data = future.result()
                    results[jid] = data
                except Exception as e:
                    warn(f"job run worker failed: {e}")
                    traceback.print_exc()

        return results

    def _due(self, key, interval, now):
        return (now - self.last_refresh.get(key, 0.0)) >= interval

    def refresh_once(self):
        start = time.time()
        now = start
        errors = 0

        auth_ok = 1 if self.client.authenticate() else 0

        with self.state_lock:
            current = dict(self.state)
            current["auth_ok"] = auth_ok

        if not auth_ok:
            current.update({
                "last_refresh_success": 0,
                "last_refresh_duration_seconds": time.time() - start,
                "last_refresh_timestamp_seconds": time.time(),
                "errors": 1,
            })
            payload = self.builder.render(current)
            self.cache.set_payload(payload)
            with self.state_lock:
                self.state = current
            return

        # Work with cached copies so one failed family does not erase good prior data.
        cluster = current.get("cluster", {})
        alerts = current.get("alerts", [])
        nodes = current.get("nodes", [])
        jobs = current.get("jobs", [])
        sources = current.get("sources", [])
        job_runs = current.get("job_runs", {})

        refreshed = []

        # Cluster and node inventory are refreshed together because cluster labels and hardware summary use both.
        if self._due("cluster", CLUSTER_REFRESH_SECONDS, now):
            try:
                nodes = get_nodes(self.client)
                cluster = get_cluster_summary(self.client, nodes=nodes, alerts=alerts, jobs=jobs)
                self.last_refresh["cluster"] = now
                refreshed.append("cluster")
            except Exception:
                errors += 1
                traceback.print_exc()

        # If cluster is not due but node stats are due, refresh node stats only.
        elif CPE_ENABLE_NODE_STATS and self._due("node_stats", NODE_STATS_REFRESH_SECONDS, now):
            try:
                nodes = get_nodes(self.client)
                self.last_refresh["node_stats"] = now
                refreshed.append("node_stats")
            except Exception:
                errors += 1
                traceback.print_exc()

        # If cluster is not due but node inventory detail is due, refresh node inventory only.
        elif CPE_ENABLE_NODE_STATS and self._due("node_stats", NODE_STATS_REFRESH_SECONDS, now):
            try:
                nodes = get_nodes(self.client)
                nodes = nodes
                self.last_refresh["node_stats"] = now
                refreshed.append("node_stats")
            except Exception:
                errors += 1
                traceback.print_exc()

        if self._due("alerts", ALERTS_REFRESH_SECONDS, now):
            try:
                alerts = get_alerts(self.client)
                self.last_refresh["alerts"] = now
                refreshed.append("alerts")
            except Exception:
                errors += 1
                traceback.print_exc()

        if self._due("jobs", JOBS_REFRESH_SECONDS, now):
            try:
                jobs = get_jobs(self.client)
                self.last_refresh["jobs"] = now
                refreshed.append("jobs")
            except Exception:
                errors += 1
                traceback.print_exc()

        if self._due("sources", SOURCES_REFRESH_SECONDS, now):
            try:
                sources = get_sources(self.client)
                self.last_refresh["sources"] = now
                refreshed.append("sources")
            except Exception:
                errors += 1
                traceback.print_exc()

        if INCLUDE_JOB_RUNS and jobs and self._due("job_runs", JOB_RUNS_REFRESH_SECONDS, now):
            try:
                job_runs = self.collect_job_run_info(jobs)
                self.last_refresh["job_runs"] = now
                refreshed.append("job_runs")
            except Exception:
                errors += 1
                traceback.print_exc()

        duration = time.time() - start

        data = {
            "auth_ok": auth_ok,
            "last_refresh_success": 1 if errors == 0 else 0,
            "last_refresh_duration_seconds": duration,
            "last_refresh_timestamp_seconds": time.time(),
            "cluster": cluster,
            "alerts": alerts,
            "nodes": nodes,
            "jobs": jobs,
            "sources": sources,
            "job_runs": job_runs,
            "errors": errors,
        }

        payload = self.builder.render(data)
        self.cache.set_payload(payload)

        with self.state_lock:
            self.state = data

        log(
            f"refresh complete duration={duration:.2f}s refreshed={','.join(refreshed) if refreshed else 'none'} "
            f"cluster={cluster.get('name', 'unknown')} jobs={len(jobs)} "
            f"alerts={len(alerts)} nodes={len(nodes)} sources={len(sources)} "
            f"job_runs={len(job_runs)} errors={errors} payload_bytes={len(payload)}"
        )

    def run(self):
        while True:
            try:
                self.refresh_once()
            except Exception as e:
                err(f"background refresh failed: {e}")
                traceback.print_exc()

            # Wake up often enough to catch the shortest configured interval without hammering APIs.
            sleep_for = max(5, min(
                REFRESH_SECONDS,
                CLUSTER_REFRESH_SECONDS,
                ALERTS_REFRESH_SECONDS,
                JOBS_REFRESH_SECONDS,
                SOURCES_REFRESH_SECONDS,
                JOB_RUNS_REFRESH_SECONDS,
                NODE_STATS_REFRESH_SECONDS,
            ))
            time.sleep(sleep_for)


cache = RenderedMetricsCache()
client = CohesityClient(vip, username, domain, password)
refresher = BackgroundRefresher(client, cache)


class OpenMetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        try:
            payload = cache.get_payload()
            self.send_response(200)
            self.send_header("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as e:
            err(f"HTTP metrics generation failed: {e}")
            traceback.print_exc()
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())


if __name__ == "__main__":
    log("starting initial background refresh")
    try:
        refresher.refresh_once()
    except Exception as e:
        err(f"initial refresh failed: {e}")
        traceback.print_exc()

    refresher.start()
    log(f"starting OpenMetrics exporter on port {port}")
    server = ThreadingHTTPServer(("", port), OpenMetricsHandler)
    server.serve_forever()
