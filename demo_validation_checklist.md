# ShadowOps Sentinel Demo Validation Checklist

Run this checklist before recording or presenting the demo.

## 1. Confirm app is installed

- Splunk shows the app label: **ShadowOps Sentinel**.
- Index exists: `shadowops`.
- Sourcetypes are visible after ingestion:
  - `shadowops:auth`
  - `shadowops:proxy`
  - `shadowops:jira`
  - `shadowops:agent`
  - `shadowops:splunk_audit`
  - `shadowops:mcp_access`
  - `shadowops:detection`

## 2. Confirm JSON extraction

Open Splunk Search and run `detections/validation_queries.spl` query V02.

The fields below must appear as extracted fields, not raw text only:

- `agent_id`
- `correlation_id`
- `registered_agent`
- `access_path`
- `sensitive_index`
- `risk_signal`
- `ticket_body`
- `dest_domain`
- `bytes_out`

If these do not extract, verify `props.conf` is loaded and the app was installed on the search head. This project uses `KV_MODE=json` for search-time JSON extraction.

## 3. Confirm attack chain

Run query V04. You should see this sequence under one `correlation_id`:

1. Malicious Jira ticket creation.
2. Rogue agent start.
3. Rogue agent reads ticket.
4. Sensitive Splunk search against `customer_payments`.
5. Sensitive Splunk search against `prod_secrets`.
6. External POST to `webhook.site`.
7. Developer token refresh.
8. Detection summary event.

## 4. Confirm rule 06 scores critical

Run query V05. Expected result:

- `severity=critical`
- `risk_score=100`
- `prompt_injection_events > 0`
- `sensitive_search_events >= 2`
- `external_egress_events > 0`

## 5. Confirm dashboard renders

Open **ShadowOps Sentinel** dashboard and verify:

- Critical Shadow Agent Detections is greater than zero.
- Approved MCP Agent Sessions is greater than zero.
- Five-Beat Demo Timeline shows safe path first and rogue chain later.
- Full Attack Chain Correlation table contains one critical row.
- MCP Safe Path vs Direct Token Bypass chart has both `mcp` and `direct_token`.

## 6. AI summary wording

Default mode is deterministic and evidence-backed:

```bash
python scripts/generate_ai_summary.py --input sample_output/shadowops_events.jsonl --output sample_output/incident_summary.md
```

Optional large-language-model mode is available when `ANTHROPIC_API_KEY` is set:

```bash
python scripts/generate_ai_summary.py --use-anthropic --input sample_output/shadowops_events.jsonl --output sample_output/incident_summary_llm.md
```

For Devpost, describe the default summary as **evidence-backed deterministic AI-style summarization** unless you actually use the optional LLM path in the submitted demo.
