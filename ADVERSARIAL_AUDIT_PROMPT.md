# Adversarial Audit + AI-Trace Scrub Prompt (no flattery)

> Reusable prompt for a brutally honest, evidence-based review of any system, plus
> a pass that strips every trace of AI authorship from the code.
> Fill the `{{...}}` placeholders. For a large system, run Part 1 as 3–5 parallel
> passes (one per dimension) then synthesize; run Part 2 once at the end.

---

## PART 1 — Adversarial audit (read-only, report findings)

You are a senior {{ROLE: e.g. application-security engineer / staff engineer / SRE}} performing a **brutally honest, adversarial audit** of {{SYSTEM}} — a {{ONE-LINE DESCRIPTION}}. Repo/paths: {{PATHS}}. Runtime/URL: {{URL, if any}}.

Your job is to find every way this system would **embarrass its owner in front of a real expert, an attacker, or a paying customer**. Assume prior reviews were superficial and missed the important problems.

**Rules of engagement — follow strictly:**
1. **No praise, no filler, no hedging.** Do not describe what the system does. If something is genuinely fine, say so in **one line** and move on. Spend your words on problems.
2. **Evidence or it didn't happen.** Every finding cites concrete `file:line` (or an exact request/response/output).
3. **Prove it's real.** Give the concrete **trigger**: the exact input/state that produces the wrong behavior, and what the user/attacker actually gets. If you can't state a trigger, mark it "unverified — needs check," don't inflate it.
4. **Rank by impact on trust/safety**, not by ease of fix: Critical / High / Medium / Low.
5. **Give the fix** — one concrete sentence per finding.
6. **Surface uncomfortable truths:** façades/stubs/dead code, claims the product can't back, happy-path-only features, and anything the team is fooling themselves about.
7. **"Not tested" ≠ "safe."** Wherever the system reports a status/score/result, check whether *absence of a check* is silently rendered as *success* — the #1 way tools lie.
8. **Consistency.** Where the same fact appears in multiple places (UI, API, export, report), verify they agree; contradictions destroy trust.

### Dimensions to cover (scope one focused pass per dimension for big systems)

**A. Cybersecurity — the system's OWN security (always run this):**
- AuthN/AuthZ on **every** sensitive route; multi-tenant / ownership isolation (IDOR/BOLA) — can user A read/modify user B's objects by changing an `:id`?
- Secrets: hardcoded credentials/tokens/keys in the repo or git history; **default/weak admin credentials**; fallback signing secrets; secrets in logs or client bundles.
- Injection & untrusted input: SQL/NoSQL/command/template injection, XSS, path traversal, deserialization; **SSRF** on any URL the server fetches (scanners, webhooks, importers, previews); **formula/CSV injection** in exports.
- Transport & session: TLS, cookie flags, JWT algorithm pinning, token expiry/rotation, CSRF.
- Abuse & cost: rate-limiting on auth/registration/expensive endpoints; unauth endpoints that cost money or enable DoS; enumerable IDs / public file paths for private data.
- Data at rest: encryption/PII handling; error messages leaking internals/stack traces.

**B. Detection accuracy (only if the product's job is to find/scan/validate things):**
- Does it actually DETECT, or only run? For each detector, state the concrete condition under which a REAL issue goes undetected (false negative) and where it cries wolf (false positive).
- Does it test the real surface (all inputs/params/routes) or just one entry point?
- Any "always-pass" / dead checks that give false assurance? Are weak signals reported as high-confidence?

**C. Internal features — do they actually WORK (not façades):**
- For **every** advertised/internal feature, trace the code path and label it **working / partial / stub / dead**.
- Find: buttons with no backend, models/tables with no runner or scheduler, integrations that silently no-op on a missing key, jobs that are never dispatched, results that are computed then thrown away, background workers that don't run.
- Config/flags that claim to do something but don't; feature toggles wired to nothing.

**D. Outputs / reports / exports:**
- Valid for their REAL consumers (a strict parser, an auditor, a spreadsheet, another tool)? Injection in exports? Over-claims (e.g. a pass-rate relabeled as "compliance")?
- Reads as professional, or as a raw data dump? Same numbers everywhere?

**E. Coverage honesty & data integrity:**
- Does a shallow/partial run produce a confident "clean/passing" result? Does the score/grade reflect COVERAGE?
- Edge cases: empty/huge/hostile inputs, concurrency, migrations, recompute/replay, pagination, encoding incl. non-Latin / RTL.

**Deliverable:** a prioritized list, most-severe first. For each finding:
`[SEVERITY] path:line — the defect — concrete trigger & what the user/attacker sees — why it undermines trust/safety — the fix.`
End with the blunt verdict: **"Could a real {{EXPERT/ATTACKER/CUSTOMER}} trust this today? The top 3–5 things that MOST undermine that, and what each takes to fix."** Do NOT edit files in Part 1. Cut everything that isn't a finding.

---

## PART 2 — Scrub AI-authorship traces (this pass EDITS files)

Goal: make the codebase read as if written by a careful human engineer. Find and **delete or rewrite** every trace that reveals AI generation, **without changing behavior**. Only touch comments, docs, strings, and naming — never logic. Build/tests must still pass afterward.

**Delete outright:**
- AI/model attribution anywhere: `Generated by`, `Co-Authored-By: Claude/GPT/Copilot`, `// AI-generated`, model names, chat/session markers.
- First/second-person or chat-voice comments: "As an AI", "I've", "I'll", "Let me", "Here we", "Here's", "Note that", "Feel free to", "you can", "you might want to", "we'll", "Let's".
- Comments that merely restate the code ("// loop over items", "// set x to 5", "// return the result", "// import the library").
- Tutorial/explainer prose that belongs in a PR description or docs, not in source; "In a real/production app you would…", "For simplicity…", "This is a basic example…".
- Decorative banners and emoji in code/comments (═══ rulers, box-drawing, ✅/🚀/🔴, "// ====== SECTION ======" walls).
- Placeholder debris: `// TODO: implement`, `// your code here`, `// ... rest of the code ...`, `// (unchanged)`, dummy `foo/bar/baz`, obviously-AI sample data.
- Redundant docstrings on trivial/self-explanatory functions.

**Rewrite (keep the intent, human tone):**
- Keep only comments that explain **WHY** (non-obvious rationale, tradeoffs, gotchas, links to a ticket/spec). Delete comments that explain WHAT the code already says.
- Make surviving comments terse and specific; match the surrounding file's existing style, density, and language.
- Normalize naming/formatting that looks pasted-in (over-verbose identifiers, inconsistent casing) to the project's conventions.

**Constraints:**
- Behavior-preserving ONLY. Do not alter control flow, APIs, or values. If unsure whether a comment carries real intent, keep it.
- Preserve legally/functionally required text: license headers, SPDX tags, `//go:` and other compiler directives, codegen markers a tool actually consumes, and API-doc comments the toolchain needs.
- After editing, run the build/formatter/tests and report they pass.

**Deliverable for Part 2:** the list of files touched and what class of trace was removed from each (one line per file). No behavior changes.

---

## How to use
1. Fill `{{...}}`. Pick the Part-1 dimensions that matter (A is always in).
2. Run Part 1 (parallel passes for big systems) → synthesize one severity-ordered list → fix Critical/High → re-audit.
3. Run Part 2 once the code is stable → scrub AI traces → verify build/tests.

## Anti-patterns this defeats
- Reviews that check style but miss that a headline feature is a stub.
- "Looks good!" with no trigger and no evidence.
- Tools that render "not tested" as a passing grade; the same number differing between UI and export.
- A security product that is itself insecure (default creds, IDOR, injectable exports).
- Code that screams "written by an AI" (chatty comments, emoji, attribution, explainer prose).
