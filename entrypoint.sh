#!/usr/bin/env bash
set -euo pipefail

ARGS=()

# Identity / policy domain
[[ -n "${ORG_NAME:-}" ]] && ARGS+=(--org-name "$ORG_NAME")
[[ -n "${REPORT_DOMAIN:-}" ]] && ARGS+=(--report-domain "$REPORT_DOMAIN")

# Email routing
[[ -n "${MAIL_FROM:-}" ]] && ARGS+=(--mail-from "$MAIL_FROM")
[[ -n "${MAIL_TO:-}" ]] && ARGS+=(--mail-to "$MAIL_TO")
[[ -n "${SMTP_HOST:-}" ]] && ARGS+=(--smtp-host "$SMTP_HOST")
[[ -n "${SMTP_PORT:-}" ]] && ARGS+=(--smtp-port "$SMTP_PORT")

# Credentials (also respected by script via env)
export SMTP_USER="${SMTP_USER:-}"
export SMTP_PASS="${SMTP_PASS:-}"

# TLS modes
[[ "${USE_SSL:-false}" == "true" ]] && ARGS+=(--ssl)
[[ "${USE_STARTTLS:-true}" != "true" ]] && ARGS+=(--no-starttls)

# Rate limits
[[ -n "${MIN_PER_HOUR:-}" ]] && ARGS+=(--min-per-hour "$MIN_PER_HOUR")
[[ -n "${MAX_PER_HOUR:-}" ]] && ARGS+=(--max-per-hour "$MAX_PER_HOUR")

# SPF include pools
[[ -n "${SPF_PASS_INCLUDES:-}" ]] && ARGS+=(--spf-pass-includes "$SPF_PASS_INCLUDES")
[[ -n "${SPF_FAIL_INCLUDES:-}" ]] && ARGS+=(--spf-fail-includes "$SPF_FAIL_INCLUDES")

# One-shot test
[[ "${ONCE:-false}" == "true" ]] && ARGS+=(--once)

exec python /app/dmarc_report_generator.py "${ARGS[@]}"
