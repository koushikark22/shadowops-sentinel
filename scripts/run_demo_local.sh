#!/usr/bin/env bash
set -euo pipefail
python generate_shadowops_events.py --output sample_output/shadowops_events.jsonl --count-baseline 500
python scripts/generate_ai_summary.py --input sample_output/shadowops_events.jsonl --output sample_output/incident_summary.md
printf '\nGenerated files:\n'
ls -lh sample_output/
printf '\nIncident summary preview:\n'
sed -n '1,40p' sample_output/incident_summary.md
