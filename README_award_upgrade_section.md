## Explainable Risk and Containment Workflow

ShadowOps Sentinel includes an evidence-backed risk explanation and a simulated containment workflow for the critical rogue-agent incident.

The risk explanation shows why the critical alert fired by listing contributing signals such as prompt injection, direct-token bypass, sensitive Splunk search activity, external webhook egress, and unregistered-agent behavior.

The containment simulation demonstrates the response path a SOC team could execute through SOAR, identity, proxy, or ticketing integrations:

- Revoke the offending agent token
- Block the external webhook destination
- Quarantine the unregistered local agent
- Create or update the incident ticket
- Export investigation evidence
- Generate a grounded analyst summary

Supporting files:

- `sample_output/risk_explanation.json`
- `sample_output/containment_actions.json`
- `docs/evaluation.md`
- `docs/threat_model.md`
- `lookups/server_registry.csv`
- `lookups/tool_sensitivity.csv`
