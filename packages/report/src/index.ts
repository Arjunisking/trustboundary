export interface ReportFindingLike {
  ruleId: string;
  severity: string;
  file: string;
  message: string;
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderPlaceholderReport(findings: ReportFindingLike[]): string {
  const title =
    findings.length === 0
      ? "No Confirmed Critical issues found"
      : `TrustBoundary findings: ${findings.length}`;

  const items = findings
    .map((finding) => {
      return [
        "<li>",
        `<strong>${escapeHtml(finding.ruleId)}</strong>`,
        ` [${escapeHtml(finding.severity)}] `,
        `${escapeHtml(finding.file)}: `,
        `${escapeHtml(finding.message)}`,
        "</li>"
      ].join("");
    })
    .join("");

  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    `<title>${escapeHtml(title)}</title>`,
    "</head>",
    "<body>",
    `<h1>${escapeHtml(title)}</h1>`,
    `<ul>${items}</ul>`,
    "</body>",
    "</html>"
  ].join("");
}
