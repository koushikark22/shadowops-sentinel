python .\generate_shadowops_events.py --output .\sample_output\shadowops_events.jsonl --count-baseline 500
python .\scripts\generate_ai_summary.py --input .\sample_output\shadowops_events.jsonl --output .\sample_output\incident_summary.md
Get-ChildItem .\sample_output
Get-Content .\sample_output\incident_summary.md -TotalCount 40
