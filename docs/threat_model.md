# ShadowOps Sentinel Threat Model

## Scope

ShadowOps Sentinel models AI agents and MCP-connected tools as non-human identities that can access enterprise systems such as Splunk, Jira, proxy services, and internal APIs.

## Primary Threats

| Threat | Description | Detection Coverage |
|---|---|---|
| Prompt injection | Malicious instructions embedded in tickets, documents, or external content influence an agent | Jira prompt-injection content plus downstream agent behavior |
| Direct-token bypass | Agent uses a token or credential path outside approved MCP approval flow | Access path, token, and MCP telemetry correlation |
| Sensitive search overreach | Agent searches protected Splunk indexes or sensitive data classes | Splunk audit events and sensitive index flags |
| External exfiltration | Agent sends data to an untrusted external domain or webhook | Proxy egress telemetry |
| Unregistered agent | Local or shadow agent operates without registry approval | Agent registry comparison |
| MCP descriptor drift | Tool description, schema, or server metadata changes without review | Server registry descriptor hash comparison |
| Caller identity confusion | Same session or token appears across multiple callers, hosts, or agents | Session/token/caller correlation analytics |

## Trust Assumptions

- The Splunk index contains JSON telemetry from agent, MCP, Jira, proxy, auth, and Splunk audit sources.
- The nested field `event.sourcetype` is treated as the logical source type.
- The demo containment workflow is simulated and represents actions a SOAR, identity, proxy, or ticketing platform could execute in production.
- No real secrets, tokens, or production systems are used in the demo dataset.
