from prometheus_client import Counter, Histogram

VALIDATIONS_TOTAL = Counter(
    "validations_total", "Email validations by final status and first reason", ["status", "reason"]
)
DNS_LOOKUP_SECONDS = Histogram(
    "dns_lookup_seconds",
    "Uncached MX lookup latency",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0),
)
DNS_LOOKUPS_TOTAL = Counter("dns_lookups_total", "Uncached MX lookups by outcome", ["outcome"])
CACHE_HITS_TOTAL = Counter("cache_hits_total", "MX cache lookups by tier (l1, l2, miss)", ["tier"])
CACHE_ERRORS_TOTAL = Counter("cache_errors_total", "Redis cache errors by operation", ["op"])
RATE_LIMIT_REJECTIONS_TOTAL = Counter("rate_limit_rejections_total", "Requests rejected (429)")
RATE_LIMIT_ERRORS_TOTAL = Counter("rate_limit_errors_total", "Rate limiter backend errors")
