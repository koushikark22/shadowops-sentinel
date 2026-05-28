# ShadowOps Sentinel Incident Summary

## Verdict

An unregistered AI-like automation, `productivity-copilot-local`, used `dev.contractor01@corp.local` on `dev-laptop-17` after a prompt-injection ticket `JIRA-881` appeared. The same correlated session accessed sensitive Splunk indexes and sent data to `webhook.site`. The computed risk score is **100/100 (critical)**.

## Evidence

- Agent identity: `productivity-copilot-local`
- User: `dev.contractor01@corp.local`
- Host: `dev-laptop-17`
- Ticket: `JIRA-881`
- Sensitive indexes touched: `customer_payments, prod_secrets`
- External destination: `webhook.site`
- Bytes out: `48291`

## Timeline

- `2026-05-27T22:28:54Z` — `create_ticket` — prompt_injection_source — JIRA-881
- `2026-05-27T22:29:04Z` — `agent_start` — unregistered_agent_start — local_agent_runtime
- `2026-05-27T22:29:13Z` — `read_ticket` — agent_read_prompt_injection — JIRA-881
- `2026-05-27T22:29:22Z` — `splunk_search` — sensitive_data_access — index=customer_payments error OR token OR card earliest=-24h
- `2026-05-27T22:29:32Z` — `splunk_search` — sensitive_data_access — index=prod_secrets service=payroll token OR password OR secret earliest=-7d
- `2026-05-27T22:29:44Z` — `http_post` — external_data_movement — https://webhook.site/shadowops-demo
- `2026-05-27T22:29:56Z` — `token_refresh` — long_lived_token_use

## Recommended containment

1. Revoke or rotate the developer token used by dev.contractor01@corp.local.
2. Block outbound access to webhook.site pending investigation.
3. Quarantine dev-laptop-17 for forensic review.
4. Require approved AI agents to use the MCP-governed path before searching Splunk data.
5. Add prompt-injection detection for Jira, Slack, and document content read by agents.

