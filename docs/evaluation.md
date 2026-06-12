# ShadowOps Sentinel Evaluation

## Demo Dataset

| Item | Value |
|---|---:|
| Total events | 513 |
| Primary attack chains | 1 |
| Critical detections | 1 |
| Primary detection | Shadow Agent Prompt Injection Exfiltration |
| Primary agent | productivity-copilot-local |
| Primary user | dev.contractor01@corp.local |
| Risk score | 94 |

## Validation Results

| Metric | Result |
|---|---:|
| Full-chain attack scenario detected | 1 / 1 |
| Critical detection generated | Yes |
| Explanation completeness | 100% |
| Containment simulation completed | 6 / 6 actions |
| False positives in demo dataset | 0 |
| Demo reproducibility | Validated locally in Splunk Enterprise |

## Validated Detection Chain

1. Prompt-injection ticket observed.
2. Unregistered local agent accessed the ticket.
3. Agent searched sensitive Splunk indexes.
4. Agent posted data to an external webhook.
5. ShadowOps Sentinel generated a critical detection.
6. Containment workflow simulated token revocation, webhook blocking, agent quarantine, incident creation, evidence export, and analyst-summary generation.

## SPL Validation Queries

### Event Count

```spl
index=shadowops
| stats count
```

Expected result: `513`

### Logical Source Type Breakdown

```spl
index=shadowops
| spath path=event.sourcetype output=real_sourcetype
| stats count by real_sourcetype
| sort real_sourcetype
```

### Critical Detection

```spl
index=shadowops
| spath path=event.sourcetype output=real_sourcetype
| search real_sourcetype="shadowops:detection"
| spath
| table _time event.detection_name event.severity event.risk_score event.agent_id event.user event.summary
```
