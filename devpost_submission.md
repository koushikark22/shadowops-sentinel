# ShadowOps Sentinel: Detect and Contain the AI Agents Nobody Approved

## Inspiration

Enterprises are rapidly adopting autonomous AI agents, but security teams often cannot answer basic questions: Which agents are running? Are they approved? What data did they touch? Did a prompt injection cause their behavior? Did they bypass the governed access path?

ShadowOps Sentinel treats AI agents as a new class of machine identity and gives defenders visibility into rogue agent behavior.

## What it does

ShadowOps Sentinel discovers unapproved AI-like automation, correlates prompt-injection content with downstream tool misuse, detects sensitive Splunk searches and external data movement, and generates an evidence-backed containment plan.

The demo shows two paths:

1. A registered `security-triage-agent` uses a safe MCP-approved path.
2. A rogue `productivity-copilot-local` bypasses governance using a developer token, reads a poisoned Jira ticket, searches sensitive Splunk indexes, and posts data to an external webhook.

Splunk correlates the attack chain and produces a critical-risk detection.

## How we built it

- Python synthetic telemetry generator
- Splunk HTTP Event Collector compatible JSON events
- ShadowOps sourcetypes for auth, proxy, Jira, agent runtime, Splunk audit, MCP access, and detections
- SPL rules for behavioral fingerprinting, prompt-injection detection, sensitive search detection, egress detection, and full attack-chain correlation
- Splunk app skeleton with index, props, saved searches, lookup, and dashboard
- Evidence-backed incident summary generator

## Splunk usage

- Splunk HTTP Event Collector for ingestion
- Splunk indexes and sourcetypes for cross-source operational data
- SPL for correlation and risk scoring
- Splunk dashboard for the five-beat demo story
- MCP-governed path simulated through `shadowops:mcp_access`, with a clear fallback strategy for environments where real Splunk MCP Server access is unavailable

## What makes it unique

Most AI security demos summarize alerts. ShadowOps Sentinel focuses on an emerging enterprise gap: detecting and governing the AI agents that nobody registered. It contrasts approved MCP-style access with direct-token bypass behavior, then reconstructs a prompt-injection-to-exfiltration chain.

## Challenges

The main design challenge was avoiding weak user-agent-only detection. The project uses behavioral fingerprinting instead: unregistered agent identity, direct-token access, sensitive index queries, prompt-injection proximity, and external egress.

## What's next

- Replace simulated MCP access events with real Splunk MCP Server telemetry
- Add Splunk AI Toolkit anomaly detection for baseline deviation
- Add SOAR integration for token revocation and webhook blocking
- Package as a full Splunkbase-ready app


## Demo honesty note

The submitted prototype includes deterministic evidence-backed incident summarization so the narrative is reproducible and traceable to Splunk event evidence. An optional Anthropic-powered large-language-model mode is included for teams that want to generate the final narrative from the same evidence bundle during the demo.
