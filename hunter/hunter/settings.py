"""Depth profiles and derived limits.

The operator can ask for `fast`, `standard` or `deep`; the per-target time
budget can only *reduce* that profile, never silently upgrade it.  This keeps
small test budgets cheap while letting real runs go much deeper.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

ORDER = {"fast": 0, "standard": 1, "deep": 2}


@dataclass(frozen=True)
class Settings:
    profile: str
    crawl_pages: int
    crawl_depth: int
    bundle_limit: int
    map_limit: int
    leak_limit: int
    graphql_limit: int
    max_payloads: int
    max_requests_per_endpoint: int
    max_endpoints: int
    param_limit: int
    ai_rounds: int

    def as_dict(self) -> dict:
        return asdict(self)


PROFILES = {
    "fast": Settings(
        profile="fast",
        crawl_pages=6,
        crawl_depth=1,
        bundle_limit=5,
        map_limit=2,
        leak_limit=8,
        graphql_limit=6,
        max_payloads=4,
        max_requests_per_endpoint=15,
        max_endpoints=3,
        param_limit=2,
        ai_rounds=1,
    ),
    "standard": Settings(
        profile="standard",
        crawl_pages=20,
        crawl_depth=2,
        bundle_limit=12,
        map_limit=3,
        leak_limit=16,
        graphql_limit=8,
        max_payloads=6,
        max_requests_per_endpoint=20,
        max_endpoints=8,
        param_limit=3,
        ai_rounds=2,
    ),
    "deep": Settings(
        profile="deep",
        crawl_pages=45,
        crawl_depth=3,
        bundle_limit=22,
        map_limit=6,
        leak_limit=28,
        graphql_limit=10,
        max_payloads=8,
        max_requests_per_endpoint=30,
        max_endpoints=15,
        param_limit=5,
        ai_rounds=2,
    ),
}


def budget_tier(per_target_seconds: float) -> str:
    if per_target_seconds < 300:
        return "fast"
    if per_target_seconds < 600:
        return "standard"
    return "deep"


def resolve(profile: str, per_target_seconds: float, ai_requested: int | None = None) -> Settings:
    requested = profile if profile in PROFILES else "deep"
    tier = budget_tier(per_target_seconds)
    effective = requested if ORDER[requested] <= ORDER[tier] else tier
    base = PROFILES[effective]
    rounds = base.ai_rounds if ai_requested is None else max(1, min(3, int(ai_requested)))
    return Settings(
        profile=base.profile,
        crawl_pages=base.crawl_pages,
        crawl_depth=base.crawl_depth,
        bundle_limit=base.bundle_limit,
        map_limit=base.map_limit,
        leak_limit=base.leak_limit,
        graphql_limit=base.graphql_limit,
        max_payloads=base.max_payloads,
        max_requests_per_endpoint=base.max_requests_per_endpoint,
        max_endpoints=base.max_endpoints,
        param_limit=base.param_limit,
        ai_rounds=rounds,
    )
