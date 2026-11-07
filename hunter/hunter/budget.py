"""Hard deadlines, request ceilings and the emergency watchdog.

No code path in hunter is allowed to run forever.  Every loop checks either a
deadline or a hard iteration counter, and the watchdog is a final backstop that
flushes reports to disk before terminating the process.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass


class BudgetExceeded(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


PHASE_FRACTIONS = {
    "recon": 0.40,
    "select": 0.05,
    "tests": 0.40,
    "validate": 0.10,
    "report": 0.05,
}


@dataclass
class BudgetState:
    global_deadline: float
    target_deadline: float
    target_started: float
    target_seconds: float
    phase_deadline: float


class Budget:
    def __init__(self, max_minutes: float, per_target_seconds: float, max_requests: int, max_total_requests: int):
        self.started = time.monotonic()
        self.global_deadline = self.started + max(0.0, float(max_minutes)) * 60.0
        self.per_target_seconds = max(1.0, float(per_target_seconds))
        self.target_seconds = self.per_target_seconds
        self.max_requests = max(1, int(max_requests))
        self.max_total_requests = max(1, int(max_total_requests))
        self.requests_total = 0
        self.requests_target = 0
        self.target_started = self.started
        self.target_deadline = self.global_deadline
        self._lock = threading.RLock()
        self.requests_by_phase: dict[str, int] = {}
        self.requests_by_endpoint: dict[str, int] = {}
        self.phase_marks: dict[str, float] = {}

    def start_target(self, host: str) -> None:
        with self._lock:
            now = time.monotonic()
            self.target_started = now
            self.target_deadline = min(now + self.per_target_seconds, self.global_deadline)
            self.requests_target = 0
            self.requests_by_phase = {}
            self.requests_by_endpoint = {}
            self.phase_marks = {"target": now}

    def target_remaining(self) -> float:
        return max(0.0, self.target_deadline - time.monotonic())

    def global_remaining(self) -> float:
        return max(0.0, self.global_deadline - time.monotonic())

    def mark_phase(self, phase: str) -> None:
        self.phase_marks[phase] = time.monotonic()

    def phase_deadline(self, phase: str) -> float:
        base = self.phase_marks.get(phase, time.monotonic())
        fraction = PHASE_FRACTIONS.get(phase, 1.0)
        return min(base + self.target_seconds * fraction, self.target_deadline)

    def check_global(self) -> None:
        if time.monotonic() >= self.global_deadline:
            raise BudgetExceeded("orçamento global de tempo esgotado")

    def check_target(self) -> None:
        self.check_global()
        if time.monotonic() >= self.target_deadline:
            raise BudgetExceeded("orçamento de tempo do alvo esgotado")

    def check_phase(self, phase: str) -> None:
        self.check_target()
        if time.monotonic() >= self.phase_deadline(phase):
            raise BudgetExceeded(f"orçamento de tempo da fase {phase} esgotado")

    def request_allowed(self) -> tuple[bool, str]:
        if time.monotonic() >= self.global_deadline:
            return False, "orçamento global de tempo esgotado"
        if time.monotonic() >= self.target_deadline:
            return False, "orçamento de tempo do alvo esgotado"
        if self.requests_total >= self.max_total_requests:
            return False, "teto global de requisições atingido"
        if self.requests_target >= self.max_requests:
            return False, "teto de requisições do alvo atingido"
        return True, ""

    def consume_request(self, phase: str = "recon", endpoint: str = "") -> None:
        with self._lock:
            allowed, reason = self.request_allowed()
            if not allowed:
                raise BudgetExceeded(reason)
            self.requests_total += 1
            self.requests_target += 1
            self.requests_by_phase[phase] = self.requests_by_phase.get(phase, 0) + 1
            if endpoint:
                self.requests_by_endpoint[endpoint] = self.requests_by_endpoint.get(endpoint, 0) + 1

    def expired_reason(self) -> str | None:
        if time.monotonic() >= self.global_deadline:
            return "orçamento global de tempo esgotado"
        if self.requests_total >= self.max_total_requests:
            return "teto global de requisições atingido"
        return None

    def summary(self) -> dict:
        return {
            "elapsed_seconds": round(time.monotonic() - self.started, 2),
            "global_remaining_seconds": round(self.global_remaining(), 2),
            "target_remaining_seconds": round(self.target_remaining(), 2),
            "requests_total": self.requests_total,
            "requests_target": self.requests_target,
            "requests_by_phase": dict(self.requests_by_phase),
            "requests_by_endpoint": dict(self.requests_by_endpoint),
            "max_requests": self.max_requests,
            "max_total_requests": self.max_total_requests,
        }


class Watchdog(threading.Thread):
    """Daemon watchdog: stop_event.wait(1) polling, then emergency flush."""

    def __init__(self, budget: Budget, on_expire):
        super().__init__(name="hunter-watchdog", daemon=True)
        self.budget = budget
        self.on_expire = on_expire
        self.stop_event = threading.Event()
        self.fired = False

    def stop(self) -> None:
        self.stop_event.set()

    def run(self) -> None:  # noqa: D401
        # limite: 1 iteração por segundo; termina via stop_event ou expiração.
        while not self.stop_event.wait(1.0):
            reason = self.budget.expired_reason()
            if reason:
                self.fired = True
                try:
                    self.on_expire(reason)
                finally:
                    os._exit(0)
