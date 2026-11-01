# User Guide

## Dashboard
The dashboard summarizes overall technique coverage, detection coverage, prevention coverage, and tactic-level coverage. The gap table shows up to 25 currently unmapped techniques.

## ATT&CK Matrix
Search by ATT&CK ID or technique name. Filter by tactic and status. The table includes platforms, number of mappings, and current status. Export the filtered view as CSV.

## Manage Mappings
Create one record for each relationship between a defensive control and an ATT&CK technique. For example, one SIEM rule may be mapped to more than one technique; create one mapping per technique. Likewise, multiple independent controls can map to the same technique.

Use evidence fields to make the assessment auditable:
- Evidence: rule ID, policy name, test case, ticket, or control reference.
- Data source: telemetry needed for the detection/control.
- Owner: team or product responsible.
- Confidence: analyst confidence from 1 to 5.
- Notes: scope, validation date, exclusions, known limitations.

## Import / Export
CSV import supports bulk mapping creation. Invalid technique IDs are skipped. CSV and Navigator layer JSON exports are available when mappings exist.

## Good assessment practice
Do not mark a technique Covered merely because a vendor advertises a capability. Verify required telemetry is enabled, the rule/policy is deployed, alert routing works, and a controlled test produces the expected result. Keep the evidence reference and validation notes current.
