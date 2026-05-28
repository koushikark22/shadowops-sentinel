#!/usr/bin/env python3
"""Generate an evidence-backed incident narrative from ShadowOps JSONL events.

Default mode is deterministic and rule-based so the demo is reproducible and the
summary is visibly grounded in event evidence. Optional Anthropic mode can turn the
same extracted evidence into a large-language-model narrative when ANTHROPIC_API_KEY
is available.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Tuple

NORMAL_INTERNAL_DOMAINS = {
    "jira.corp.local",
    "github.corp.local",
    "slack.corp.local",
    "servicenow.corp.local",
    "confluence.corp.local",
    "splunk.corp.local",
    "okta.corp.local",
}


def load_events(path: str) -> List[Dict[str, Any]]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                payload = json.loads(line)
                rows.append(payload.get("event", payload))
    rows.sort(key=lambda e: e.get("timestamp", ""))
    return rows


def pick_rogue_chain(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    chains = defaultdict(list)
    for e in events:
        cid = e.get("correlation_id")
        if cid:
            chains[cid].append(e)
    if not chains:
        return []
    return max(
        chains.values(),
        key=lambda xs: sum(1 for e in xs if e.get("risk_signal") not in (None, "normal_proxy", "normal_auth")),
    )


def risk_score(chain: List[Dict[str, Any]]) -> int:
    score = 0
    if any(e.get("registered_agent") is False and e.get("agent_id") for e in chain):
        score += 20
    if any(e.get("sensitive_index") is True for e in chain):
        score += 25
    if any(e.get("prompt_injection") is True for e in chain):
        score += 20
    if any(
        e.get("dest_domain") and e.get("dest_domain") not in NORMAL_INTERNAL_DOMAINS
        for e in chain
    ):
        score += 20
    if any(e.get("token_id") for e in chain):
        score += 10
    if sum(1 for e in chain if e.get("action") == "splunk_search") >= 2:
        score += 15
    return min(score, 100)


def extract_evidence(chain: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not chain:
        return {}
    agent_id = next((e.get("agent_id") for e in chain if e.get("agent_id")), "unknown")
    user = next(
        (e.get("user") for e in chain if e.get("agent_id") == agent_id and e.get("user")),
        next((e.get("user") for e in chain if e.get("user")), "unknown"),
    )
    host = next(
        (e.get("host") for e in chain if e.get("agent_id") == agent_id and e.get("host")),
        next((e.get("host") for e in chain if e.get("host")), "unknown"),
    )
    ticket = next((e.get("ticket_id") for e in chain if e.get("ticket_id")), "unknown")
    external = next(
        (
            e.get("dest_domain")
            for e in chain
            if e.get("dest_domain") and not str(e.get("dest_domain", "")).endswith("corp.local")
        ),
        "none",
    )
    bytes_out = sum(int(e.get("bytes_out") or 0) for e in chain if e.get("dest_domain") == external)
    sensitive_searches = [e for e in chain if e.get("sensitive_index") is True]
    sensitive_indexes = sorted({idx for e in sensitive_searches for idx in e.get("indexes_touched", [])})
    score = risk_score(chain)
    severity = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 31 else "low"

    timeline = []
    for e in chain:
        if e.get("sourcetype") == "shadowops:detection":
            continue
        detail = e.get("search") or e.get("dest_url") or e.get("ticket_id") or e.get("tool_name") or ""
        timeline.append(
            {
                "timestamp": e.get("timestamp", ""),
                "sourcetype": e.get("sourcetype", ""),
                "action": e.get("action", "unknown"),
                "risk_signal": e.get("risk_signal", ""),
                "detail": detail,
            }
        )

    return {
        "agent_id": agent_id,
        "user": user,
        "host": host,
        "ticket": ticket,
        "external_destination": external,
        "bytes_out": bytes_out,
        "sensitive_indexes": sensitive_indexes,
        "risk_score": score,
        "severity": severity,
        "timeline": timeline,
        "recommended_actions": [
            f"Revoke or rotate the developer token used by {user}.",
            f"Block outbound access to {external} pending investigation.",
            f"Quarantine {host} for forensic review.",
            "Require approved AI agents to use the MCP-governed path before searching Splunk data.",
            "Add prompt-injection detection for Jira, Slack, and document content read by agents.",
        ],
    }


def deterministic_summary(evidence: Dict[str, Any]) -> str:
    if not evidence:
        return "# ShadowOps Sentinel Incident Summary\n\nNo correlated rogue-agent chain was found in the supplied data."

    timeline_lines = []
    for item in evidence["timeline"]:
        detail = f" — {item['detail']}" if item.get("detail") else ""
        timeline_lines.append(
            f"- `{item['timestamp']}` — `{item['action']}` — {item['risk_signal']}{detail}"
        )
    actions = "\n".join(f"{i}. {a}" for i, a in enumerate(evidence["recommended_actions"], 1))

    return f"""# ShadowOps Sentinel Incident Summary

## Verdict

An unregistered AI-like automation, `{evidence['agent_id']}`, used `{evidence['user']}` on `{evidence['host']}` after a prompt-injection ticket `{evidence['ticket']}` appeared. The same correlated session accessed sensitive Splunk indexes and sent data to `{evidence['external_destination']}`. The computed risk score is **{evidence['risk_score']}/100 ({evidence['severity']})**.

## Evidence

- Agent identity: `{evidence['agent_id']}`
- User: `{evidence['user']}`
- Host: `{evidence['host']}`
- Ticket: `{evidence['ticket']}`
- Sensitive indexes touched: `{', '.join(evidence['sensitive_indexes']) if evidence['sensitive_indexes'] else 'none'}`
- External destination: `{evidence['external_destination']}`
- Bytes out: `{evidence['bytes_out']}`

## Timeline

{chr(10).join(timeline_lines)}

## Recommended containment

{actions}
"""


def anthropic_summary(evidence: Dict[str, Any], model: str) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set. Run without --use-anthropic or set the key.")

    prompt = (
        "You are writing a concise security incident summary for a Splunk hackathon demo. "
        "Only use the evidence in the JSON. Do not invent facts. Include Verdict, Evidence, Timeline, "
        "and Recommended containment sections. Evidence JSON:\n"
        + json.dumps(evidence, indent=2, sort_keys=True)
    )
    payload = {
        "model": model,
        "max_tokens": 1200,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Anthropic API error {e.code}: {body}") from e

    parts = data.get("content", [])
    text = "\n".join(part.get("text", "") for part in parts if part.get("type") == "text")
    return text.strip() or deterministic_summary(evidence)


def summarize(path: str, use_anthropic: bool = False, model: str = "claude-3-5-haiku-latest") -> Tuple[str, Dict[str, Any]]:
    events = load_events(path)
    chain = pick_rogue_chain(events)
    evidence = extract_evidence(chain)
    if use_anthropic and evidence:
        return anthropic_summary(evidence, model), evidence
    return deterministic_summary(evidence), evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="sample_output/shadowops_events.jsonl")
    parser.add_argument("--output", default="sample_output/incident_summary.md")
    parser.add_argument("--evidence-output", default="sample_output/incident_evidence.json")
    parser.add_argument("--use-anthropic", action="store_true", help="Generate the narrative with Anthropic using ANTHROPIC_API_KEY.")
    parser.add_argument("--anthropic-model", default="claude-3-5-haiku-latest")
    args = parser.parse_args()

    summary, evidence = summarize(args.input, args.use_anthropic, args.anthropic_model)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(summary + "\n")
    with open(args.evidence_output, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2, sort_keys=True)
    print(f"Wrote {args.output}")
    print(f"Wrote {args.evidence_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
