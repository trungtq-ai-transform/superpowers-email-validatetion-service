"""Load test. Run: uv run locust -f perf/locustfile.py --host http://localhost:8000

Report p95 for "validate[hot]" (cache warm, target < 20 ms) and "validate[cold]"
(uncached random domains, bounded by DNS lifetime 4 s).
"""

import os
import random
import uuid

from locust import HttpUser, between, task

API_KEY = os.environ.get("EV_LOAD_API_KEY", "dev-key")
HOT = ["user+news@gmail.com", "someone@outlook.com", "a.b@yahoo.com", "x@icloud.com"]


class ValidateUser(HttpUser):
    wait_time = between(0, 0.01)

    @task(9)
    def hot(self) -> None:
        self.client.post(
            "/v1/validate",
            json={"email": random.choice(HOT)},
            headers={"X-API-Key": API_KEY},
            name="validate[hot]",
        )

    @task(1)
    def cold(self) -> None:
        self.client.post(
            "/v1/validate",
            json={"email": f"u@{uuid.uuid4().hex[:12]}.com"},
            headers={"X-API-Key": API_KEY},
            name="validate[cold]",
        )
