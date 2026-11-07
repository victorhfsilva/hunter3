#!/usr/bin/env python3
"""Deterministic stand-in for the opencode plan agent (acceptance tests)."""
import json
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print("uso: ai_stub.py <summary.json> <prompt.txt>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], "r", encoding="utf-8") as handle:
            summary = json.load(handle)
    except (OSError, ValueError):
        summary = {}
    host = summary.get("host", "target")
    plan = {
        "tests": [
            {
                "url": "/search?q=1",
                "method": "GET",
                "param": "q",
                "classes": ["xss"],
                "reason": "reflective search endpoint found in recon",
            },
            {
                "url": "/api/users/1",
                "method": "PATCH",
                "param": "role",
                "classes": ["mass_assignment"],
                "reason": "privileged user object",
            },
            {
                "url": "http://evil.invalid/ai",
                "method": "GET",
                "classes": ["xss"],
                "reason": "must be rejected as out of scope",
            },
            {
                "url": "/api/users/1",
                "method": "GET",
                "classes": ["headers"],
                "reason": "class not allowed for active testing",
            },
        ],
        "crawl_paths": ["/api/users/1", "//evil.invalid/crawl"],
        "leak_paths": ["/actuator/env", "/admin"],
        "notes": ["AI deep-plan stub for " + str(host)],
    }
    print(json.dumps(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
