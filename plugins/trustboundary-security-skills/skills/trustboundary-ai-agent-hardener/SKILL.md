---
name: trustboundary-ai-agent-hardener
description: Review and fix AI-agent and LLM app trust boundaries with focus on prompt injection risk, excessive tool permissions, sensitive data in model context, approval gates, tool scoping, and least privilege. Use when Codex needs to harden AI-driven app code or guidance without turning those patterns into active TrustBoundary blockers.
---

# TrustBoundary AI Agent Hardener

## Trigger conditions
- Review agent tools with file, shell, billing, admin, or credential access.
- Tighten prompt-to-tool trust boundaries.
- Reduce sensitive data sent into model context.
- Add approval gates for high-impact actions.
- Improve docs, examples, or future learning guidance about AI-agent hardening.

## Read-first checklist
- Read `AGENTS.md`.
- Read `README.md`, `docs/non-goals.md`, and `docs/security-master-checklist.md`.
- Read `docs/security-learning-model.md`, `docs/attack-patterns.md`, and `docs/rule-to-attack-map.md`.
- Inspect relevant agent orchestration code, tool definitions, policy layers, and examples.

## Review checklist
- Check whether untrusted input can influence tool choice or tool arguments too directly.
- Check whether powerful tools exceed least-privilege need.
- Check whether high-impact actions require explicit approval.
- Check whether secrets, user records, or internal docs are pushed into model context without minimization.
- Keep classification clear: advisory or docs-only unless another active blocker surface is involved.

## Safe patch guidance
- Separate trusted instructions from untrusted user or remote content.
- Scope tools to minimum capability needed for task.
- Require approval before destructive or high-trust actions.
- Minimize model context and redact secrets or sensitive fields.
- Validate tool inputs and outputs before side effects.

## Unsafe content rules
- Do not describe prompt-injection execution tactics.
- Do not include unsafe prompt strings, offensive ideas, or real-world misuse guidance.
- Do not imply AI-agent risks are current automated TrustBoundary blockers.
- Do not change scanner enforcement, rule IDs, CLI behavior, JSON output, GitHub Action behavior, or clean report wording.

## Output format
- Label issue as advisory or docs-only.
- Name exact trust boundary gap in agent flow.
- Describe least-privilege, approval, and context-minimization fix.
- Separate code changes from educational wording changes when both exist.

## Done criteria
- Agent tools and actions follow least privilege.
- Sensitive context sent to models is minimized and redacted where needed.
- High-impact actions require explicit approval or equivalent control.
- Docs and examples remain defensive and enforcement-accurate.
