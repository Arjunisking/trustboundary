import type { Finding, ScanSummary } from "@trustboundary/core";

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderSummaryList(summary: ScanSummary, targetPath: string): string {
  return [
    '<dl class="summary-grid">',
    `<div><dt>Target</dt><dd>${escapeHtml(targetPath)}</dd></div>`,
    `<div><dt>Total findings</dt><dd>${summary.totalFindings}</dd></div>`,
    `<div><dt>Confirmed Critical</dt><dd>${summary.confirmedCriticalCount}</dd></div>`,
    `<div><dt>Status</dt><dd>${escapeHtml(summary.statusMessage)}</dd></div>`,
    "</dl>"
  ].join("");
}

function renderFindingCard(finding: Finding): string {
  return [
    '<article class="finding-card">',
    `<h3>${escapeHtml(finding.id)}</h3>`,
    '<dl class="finding-grid">',
    `<div><dt>ruleId</dt><dd>${escapeHtml(finding.ruleId)}</dd></div>`,
    `<div><dt>severity</dt><dd>${escapeHtml(finding.severity)}</dd></div>`,
    `<div><dt>confidence</dt><dd>${escapeHtml(finding.confidence)}</dd></div>`,
    `<div><dt>file</dt><dd>${escapeHtml(finding.file)}</dd></div>`,
    `<div><dt>line</dt><dd>${finding.line ?? ""}</dd></div>`,
    `<div><dt>message</dt><dd>${escapeHtml(finding.message)}</dd></div>`,
    `<div><dt>exploitPath</dt><dd>${escapeHtml(finding.exploitPath ?? "")}</dd></div>`,
    `<div><dt>patch</dt><dd>${escapeHtml(finding.patch ?? "")}</dd></div>`,
    "</dl>",
    "</article>"
  ].join("");
}

export interface ReportDocumentInput {
  targetPath: string;
  summary: ScanSummary;
  findings: Finding[];
}

export function renderHtmlReport(input: ReportDocumentInput): string {
  const title =
    input.findings.length > 0
      ? `TrustBoundary findings: ${input.summary.totalFindings}`
      : "No Confirmed Critical issues found";

  const findingsMarkup = input.findings
    .map((finding) => {
      return renderFindingCard(finding);
    })
    .join("");

  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${escapeHtml(title)}</title>`,
    "<style>",
    ":root { color-scheme: light; font-family: Georgia, 'Times New Roman', serif; }",
    "body { margin: 0; background: #f4efe7; color: #1a1714; }",
    "main { max-width: 980px; margin: 0 auto; padding: 40px 20px 64px; }",
    "h1, h2, h3 { margin: 0; }",
    "p { line-height: 1.5; }",
    ".hero { background: linear-gradient(135deg, #fff8ec, #f3dfc3); border: 1px solid #d6b98e; border-radius: 20px; padding: 24px; box-shadow: 0 18px 40px rgba(66, 38, 8, 0.08); }",
    ".status { margin-top: 16px; font-weight: 700; }",
    ".summary-grid, .finding-grid { display: grid; gap: 12px; }",
    ".summary-grid { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin: 24px 0 0; }",
    ".summary-grid div, .finding-grid div { background: rgba(255,255,255,0.7); border: 1px solid #dcc4a2; border-radius: 14px; padding: 12px; }",
    "dt { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: #7a6043; }",
    "dd { margin: 8px 0 0; font-weight: 600; white-space: pre-wrap; overflow-wrap: anywhere; }",
    ".section { margin-top: 28px; }",
    ".finding-list { display: grid; gap: 16px; }",
    ".finding-card { background: #fffdf9; border: 1px solid #d9c09e; border-radius: 18px; padding: 18px; }",
    ".finding-card h3 { font-size: 18px; margin-bottom: 14px; }",
    ".empty { background: #fffdf9; border: 1px dashed #b89b73; border-radius: 16px; padding: 18px; }",
    "</style>",
    "</head>",
    "<body>",
    "<main>",
    '<section class="hero">',
    `<h1>${escapeHtml(title)}</h1>`,
    '<p>Deterministic repository evidence scan. This report is limited in scope and not a full assessment.</p>',
    `<p class="status">${escapeHtml(input.summary.statusMessage)}</p>`,
    renderSummaryList(input.summary, input.targetPath),
    "</section>",
    '<section class="section">',
    "<h2>Findings</h2>",
    input.findings.length === 0
      ? `<div class="empty">${escapeHtml("No Confirmed Critical issues found.")}</div>`
      : `<div class="finding-list">${findingsMarkup}</div>`,
    "</section>",
    "</main>",
    "</body>",
    "</html>"
  ].join("");
}
