#!/usr/bin/env sh
# =============================================================================
# Seku CI scan — portable POSIX runner for GitHub Actions, GitLab CI, or any
# pipeline. Creates/reuses a target, runs a scan, waits, exports SARIF, and
# fails the build when findings meet or exceed a severity threshold.
#
# Depends only on: sh, curl, jq  (both ubuntu-latest and alpine have these,
# alpine needs `apk add --no-cache curl jq`).
#
# Configure via env (all overridable; CLI flags not needed):
#   SEKU_API_KEY   (required) API key, starts with vsk_  — create it in
#                  Account → API Keys, store as a CI secret.
#   SEKU_TARGET    (required) full URL to scan, e.g. https://app.example.com
#   SEKU_API_URL   API base (default https://sec.erticaz.com/api)
#   SEKU_POLICY    light | standard | deep   (default standard — free)
#                  deep is pay-per-scan; a non-admin key gets HTTP 402 without credit.
#   SEKU_FAIL_ON   none | low | medium | high | critical  (default high)
#                  build fails if any FAILING finding is >= this severity.
#   SEKU_COUNT_WARN  set to 1 to also count "warn" findings toward the gate.
#   SEKU_SARIF_OUT   path to write SARIF (default seku-results.sarif)
#   SEKU_TIMEOUT     max seconds to wait for the scan (default 900)
#   SEKU_POLL        poll interval seconds (default 10)
#
# Optional policy-as-code: a `.seku.yml` at the repo root may set `policy:` and
# `fail_on:` (scalar values); env vars always win over the file.
#
# Exit codes: 0 clean/under-threshold · 1 threshold breached · 2 config/scan error.
# =============================================================================
set -eu

err()  { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; }
info() { printf '\033[36m▸ %s\033[0m\n'  "$*" >&2; }
ok()   { printf '\033[32m✔ %s\033[0m\n'  "$*" >&2; }

# --- optional .seku.yml (scalar policy/fail_on only; env still overrides) -----
seku_yml_get() { # $1=key -> value or empty (first match, trims quotes/space)
  [ -f .seku.yml ] || return 0
  sed -n "s/^[[:space:]]*$1:[[:space:]]*//p" .seku.yml | head -1 \
    | sed 's/#.*$//' | tr -d '"'"'"'' | tr -d '[:space:]'
}

API_URL="${SEKU_API_URL:-https://sec.erticaz.com/api}"
POLICY="${SEKU_POLICY:-$(seku_yml_get policy)}";    POLICY="${POLICY:-standard}"
FAIL_ON="${SEKU_FAIL_ON:-$(seku_yml_get fail_on)}"; FAIL_ON="${FAIL_ON:-high}"
SARIF_OUT="${SEKU_SARIF_OUT:-seku-results.sarif}"
TIMEOUT="${SEKU_TIMEOUT:-900}"
POLL="${SEKU_POLL:-10}"
COUNT_WARN="${SEKU_COUNT_WARN:-0}"

[ -n "${SEKU_API_KEY:-}" ] || { err "SEKU_API_KEY is required (create one in Account → API Keys)."; exit 2; }
[ -n "${SEKU_TARGET:-}" ]  || { err "SEKU_TARGET is required (full URL to scan)."; exit 2; }
command -v curl >/dev/null || { err "curl not found"; exit 2; }
command -v jq   >/dev/null || { err "jq not found (apk add --no-cache jq)"; exit 2; }

sev_rank() { case "$1" in critical) echo 4;; high) echo 3;; medium) echo 2;; low) echo 1;; *) echo 0;; esac; }
GATE_RANK=$(sev_rank "$FAIL_ON")

# api METHOD PATH [BODY]  -> prints raw response: <body>\n<http_code>.
# The http code is emitted by curl -w on the LAST line; the caller splits it out
# with code()/body(). (Never rely on a global set inside $(...) — that is a
# subshell and the assignment would not reach the caller.)
api() {
  _m="$1"; _p="$2"; _b="${3:-}"
  if [ -n "$_b" ]; then
    curl -sS -m 60 -w '\n%{http_code}' -X "$_m" "$API_URL$_p" \
      -H "X-API-Key: $SEKU_API_KEY" -H 'Content-Type: application/json' -d "$_b" || true
  else
    curl -sS -m 60 -w '\n%{http_code}' -X "$_m" "$API_URL$_p" \
      -H "X-API-Key: $SEKU_API_KEY" || true
  fi
}
code() { printf '%s' "$1" | tail -n1; }
body() { printf '%s' "$1" | sed '$d'; }

info "Seku CI scan → $SEKU_TARGET  (policy=$POLICY, fail_on=$FAIL_ON)"

# --- 1) resolve target (reuse existing by URL, else create) ------------------
RESP=$(api GET "/targets?limit=200"); HTTP=$(code "$RESP"); TARGETS=$(body "$RESP")
case "$HTTP" in
  200|201) : ;;
  401) err "Auth failed (HTTP 401) — check SEKU_API_KEY."; exit 2;;
  *)   err "Could not list targets (HTTP $HTTP): $(printf '%s' "$TARGETS" | head -c 200)"; exit 2;;
esac

TID=$(printf '%s' "$TARGETS" | jq -r --arg u "$SEKU_TARGET" \
  'if type=="array" then . else (.data // .targets // []) end
   | map(select((.url // .URL)==$u)) | (.[0].ID // .[0].id // empty)')
if [ -z "$TID" ]; then
  RESP=$(api POST /targets "$(jq -nc --arg u "$SEKU_TARGET" '{url:$u,name:"ci-scan"}')")
  HTTP=$(code "$RESP"); CREATE=$(body "$RESP")
  case "$HTTP" in 200|201) : ;; *) err "Create target failed (HTTP $HTTP): $(printf '%s' "$CREATE" | head -c 200)"; exit 2;; esac
  TID=$(printf '%s' "$CREATE" | jq -r '.ID // .id // empty')
fi
[ -n "$TID" ] || { err "Could not resolve a target id."; exit 2; }
info "target id=$TID"

# --- 2) start scan -----------------------------------------------------------
BODY=$(jq -nc --argjson t "$TID" --arg p "$POLICY" '{target_ids:[$t],policy:$p,authorized:true}')
RESP=$(api POST /scans/start "$BODY"); HTTP=$(code "$RESP"); JOB=$(body "$RESP")
case "$HTTP" in
  200|201) : ;;
  402) err "Deep scan requires payment for this account (HTTP 402). Use policy=standard, or purchase a deep-scan credit."; exit 2;;
  403) err "Target not verified / limit reached (HTTP 403): $(printf '%s' "$JOB" | jq -r '.error // .' 2>/dev/null | head -c 200)"; exit 2;;
  *)   err "Start scan failed (HTTP $HTTP): $(printf '%s' "$JOB" | head -c 200)"; exit 2;;
esac
JID=$(printf '%s' "$JOB" | jq -r '.ID // .id // .job.ID // .job.id // empty')
[ -n "$JID" ] || { err "No job id in response: $JOB"; exit 2; }
info "job id=$JID — waiting (timeout ${TIMEOUT}s)…"

# --- 3) poll -----------------------------------------------------------------
ELAPSED=0; STATUS=""; JBODY=""
while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
  sleep "$POLL"; ELAPSED=$((ELAPSED+POLL))
  RESP=$(api GET "/scans/$JID"); JBODY=$(body "$RESP")
  STATUS=$(printf '%s' "$JBODY" | jq -r '.status // .Status // "unknown"' 2>/dev/null || echo unknown)
  printf '  [%4ss] %s\n' "$ELAPSED" "$STATUS" >&2
  case "$STATUS" in completed|failed|canceled) break;; esac
done
[ "$STATUS" = "completed" ] || { err "Scan did not complete (status=$STATUS)."; exit 2; }

RID=$(printf '%s' "$JBODY" | jq -r '.results[0].ID // .results[0].id // empty')
[ -n "$RID" ] || { err "No result id on completed job."; exit 2; }
ok "scan completed — result id=$RID"

# --- 4) SARIF export ---------------------------------------------------------
if curl -sS -m 60 "$API_URL/results/$RID/sarif" -H "X-API-Key: $SEKU_API_KEY" -o "$SARIF_OUT"; then
  ok "SARIF written → $SARIF_OUT"
else
  err "SARIF export failed (continuing)."
fi

# --- 5) findings + gate ------------------------------------------------------
# Quality/SEO categories are NOT security and must never fail a build (Seku scores
# them separately). Mirror the backend's sevNone set so a missing robots.txt or a
# cache-header nit can't block a deploy. The gate counts SECURITY findings only.
NONSEC='["seo","content","performance","hosting","tech_stack","passive_urls"]'
RESP=$(api GET "/results/$RID"); R=$(body "$RESP")
GRADE=$(printf '%s' "$R" | jq -r '.result.security_grade // "?"')
SCORE=$(printf '%s' "$R" | jq -r '.result.overall_score // 0 | floor')
if [ "$COUNT_WARN" = "1" ]; then SEL='(.status=="fail" or .status=="warn")'; else SEL='.status=="fail"'; fi
FIND=$(printf '%s' "$R" | jq -c --argjson ns "$NONSEC" \
  '[ .categories | to_entries[] | select((.key) as $k | ($ns|index($k))|not)
     | .value[] | select('"$SEL"') ]')
QUAL=$(printf '%s' "$R" | jq --argjson ns "$NONSEC" \
  '[ .categories | to_entries[] | select((.key) as $k | ($ns|index($k)))
     | .value[] | select('"$SEL"') ] | length')
count() { printf '%s' "$FIND" | jq --arg s "$1" '[.[]|select((.severity//"")==$s)]|length'; }
C=$(count critical); H=$(count high); M=$(count medium); L=$(count low)

echo "" >&2
info "Security: grade $GRADE  score $SCORE/1000   Critical=$C High=$H Medium=$M Low=$L   (quality/SEO not gated: $QUAL)"
printf '%s' "$FIND" | jq -r '.[]|"  \(.severity//"?"|ascii_upcase)\t\(.category)\t\(.check_name)"' \
  | sort | head -50 >&2 || true

# GitHub Actions outputs
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  { echo "grade=$GRADE"; echo "score=$SCORE"; echo "critical=$C"; echo "high=$H";
    echo "medium=$M"; echo "low=$L"; echo "sarif=$SARIF_OUT"; echo "result_id=$RID"; } >> "$GITHUB_OUTPUT"
fi

# worst failing severity vs gate
WORST=0
[ "$C" -gt 0 ] && WORST=4
[ "$WORST" -lt 3 ] && [ "$H" -gt 0 ] && WORST=3
[ "$WORST" -lt 2 ] && [ "$M" -gt 0 ] && WORST=2
[ "$WORST" -lt 1 ] && [ "$L" -gt 0 ] && WORST=1

if [ "$GATE_RANK" -gt 0 ] && [ "$WORST" -ge "$GATE_RANK" ]; then
  err "Gate FAILED: found findings at/above '$FAIL_ON'."
  exit 1
fi
ok "Gate passed (fail_on=$FAIL_ON)."
exit 0
