# TrustBoundary Report Language

## Required tone
TrustBoundary reports narrow deterministic evidence. They do not certify overall application security.

Preferred framing:
- findings are about committed repository evidence
- scope is limited to narrow deterministic critical patterns
- absence of blockers is not proof of safety

## Allowed wording
- `No Confirmed Critical issues found.`
- `0 Confirmed Critical issues blocking. 1 Critical issue suppressed by developer.`
- `TrustBoundary scans for a narrow set of deterministic critical patterns.`

## Forbidden wording
Do not use:
- `secure`
- `safe`
- `vulnerability-free`
- `passed security audit`
- `production ready`

## Suppression wording
Suppressed critical findings must still appear in the report as suppressed.

Report copy must make clear:
- suppressed critical findings did not fail CI
- suppression was developer-provided
- suppression does not mean issue resolved

## Summary wording rules
When blockers exist, report exact blocker count.

When blockers do not exist, use:

`No Confirmed Critical issues found.`

Do not replace that sentence with broader claims about security posture.
