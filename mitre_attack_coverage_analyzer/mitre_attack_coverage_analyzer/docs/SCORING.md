# Scoring and Interpretation

The analyzer uses transparent, technique-level counting rather than an opaque weighted score.

| Metric | Definition |
|---|---|
| Overall coverage | Techniques with at least one mapping / all loaded techniques |
| Detection coverage | Techniques with at least one Detection mapping / all loaded techniques |
| Prevention coverage | Techniques with at least one Prevention mapping / all loaded techniques |
| Tactic coverage | Mapped techniques for a tactic / all techniques associated with that tactic |

Technique status:
- Not covered: zero mappings.
- Partial: one or more mappings, none marked Covered.
- Covered: at least one mapping marked Covered.

Confidence is retained as context for evidence review and does not affect the coverage percentage. This is intentional: a low-confidence mapping should not be allowed to inflate the headline score. The team should agree on its own definition of validation before marking a mapping Covered.

A technique can be relevant to multiple tactics, so tactic totals overlap and should not be added together. A single mapping may support several techniques only when there is a defensible relationship; create a separate mapping record for each technique.
