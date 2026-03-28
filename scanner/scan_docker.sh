#!/bin/bash
# Arguments: $1=PROJECTS_DIR $2=REPORT_BODY
# NOTE: Variables inherited from sentinel.sh (sourced): EXCLUDE_DIRS, SCAN_DEPTH,
#       SUMMARY_*, COUNT_*, set_verdict, log_* functions
SCAN_DIR="$1"
REPORT="$2"
DEPTH="${SCAN_DEPTH:-4}"

# Secret vs safe patterns for build.args
SECRET_PATTERNS="TOKEN|SECRET|KEY|PASSWORD|API_KEY|DATABASE_URL|DB_|OPENAI|ANTHROPIC|MISTRAL|GROQ|SMTP|S3|AWS|OVH|CREDENTIAL"
SAFE_PATTERNS="NODE_ENV|NEXT_PUBLIC_|REACT_APP_|VITE_|PORT|HOST|DOMAIN|VERSION|BUILD_DATE|GIT_COMMIT|TZ|LANG"

# Build find exclusions
_DOCKER_FIND_EXCLUDES="-not -path */.git/*"
if [ -n "${EXCLUDE_DIRS:-}" ]; then
  for _d in $(echo "$EXCLUDE_DIRS" | tr ',' ' '); do
    _d=$(echo "$_d" | xargs)
    [ -z "$_d" ] && continue
    _DOCKER_FIND_EXCLUDES="$_DOCKER_FIND_EXCLUDES -not -path */$_d/*"
  done
fi

echo "## Analyse sécurité Docker" >> "$REPORT"
echo "" >> "$REPORT"

# --- Dockerfiles ---
# shellcheck disable=SC2086
find "$SCAN_DIR" -maxdepth "$DEPTH" \( -name "Dockerfile" -o -name "Dockerfile.*" \) $_DOCKER_FIND_EXCLUDES 2>/dev/null | while read df; do
  proj=$(echo "$df" | sed "s|$SCAN_DIR/||")
  echo "### Dockerfile: \`$proj\`" >> "$REPORT"

  # Secrets in ARG/ENV
  secrets_found=$(grep -n "ARG\|ENV" "$df" | grep -i -E "$SECRET_PATTERNS" 2>/dev/null || true)
  if [ -n "$secrets_found" ]; then
    log_attention "Secrets potentiels dans $proj"
    echo "- ⚠️ **Secrets dans ARG/ENV** (exposés pendant le build)" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "$secrets_found" >> "$REPORT"
    echo '```' >> "$REPORT"
    SUMMARY_SECRETS_DOCKER=$((SUMMARY_SECRETS_DOCKER + 1))
  fi

  # Sensitive files copied
  sensitive_copy=$(grep -n "COPY\|ADD" "$df" | grep -i "\.env\|\.npmrc\|credentials\|\.ssh\|\.pypirc\|\.aws" 2>/dev/null || true)
  if [ -n "$sensitive_copy" ]; then
    log_attention "Fichiers sensibles copiés dans $proj"
    echo "- ⚠️ **Fichiers sensibles copiés dans le build**" >> "$REPORT"
  fi

  # Multi-stage
  stages=$(grep -c "^FROM " "$df" || true)
  if [ "$stages" -gt 1 ] 2>/dev/null; then
    echo "- ✅ Multi-stage build ($stages stages)" >> "$REPORT"
  else
    log_info "Single-stage build: $proj"
    echo "- 💡 Single-stage build" >> "$REPORT"
    SUMMARY_SINGLE_STAGE=$((SUMMARY_SINGLE_STAGE + 1))
  fi

  # Non-root USER
  if grep -q "^USER " "$df"; then
    echo "- ✅ User non-root défini" >> "$REPORT"
  else
    log_info "Pas de USER dans $proj"
    echo "- 💡 Pas de USER — conteneur tourne en root" >> "$REPORT"
    SUMMARY_NO_USER=$((SUMMARY_NO_USER + 1))
  fi

  # pip install without lockfile
  if grep -q "pip install" "$df" && ! grep -q "requirements\|pyproject\|poetry\|uv\|pip-compile" "$df"; then
    echo "- 💡 pip install direct sans lockfile" >> "$REPORT"
  fi

  echo "" >> "$REPORT"
done

# --- docker-compose: contextualized build.args ---
# shellcheck disable=SC2086
find "$SCAN_DIR" -maxdepth "$DEPTH" \( -name "docker-compose*.yml" -o -name "docker-compose*.yaml" \) $_DOCKER_FIND_EXCLUDES 2>/dev/null | while read dc; do
  proj=$(echo "$dc" | sed "s|$SCAN_DIR/||")

  # Extract build args section
  build_section=$(grep -A20 "build:" "$dc" 2>/dev/null || true)
  args_lines=$(echo "$build_section" | grep -i "args" -A10 2>/dev/null | grep -E "^\s+-\s|^\s+\w+:" 2>/dev/null | head -20 || true)

  [ -z "$args_lines" ] && continue

  echo "### Compose: \`$proj\`" >> "$REPORT"

  has_secret=0
  has_safe=0

  while IFS= read -r arg_line; do
    [ -z "$arg_line" ] && continue
    arg_name=$(echo "$arg_line" | sed 's/.*- //;s/:.*//;s/=.*//' | xargs)
    [ -z "$arg_name" ] && continue

    if echo "$arg_name" | grep -qiE "$SECRET_PATTERNS"; then
      log_attention "Secret dans build.args: $arg_name dans $proj"
      echo "- ⚠️ build.args contient \`$arg_name\` — **secret exposé pendant le build**" >> "$REPORT"
      has_secret=1
      SUMMARY_BUILD_ARGS_SECRET=$((SUMMARY_BUILD_ARGS_SECRET + 1))
    elif echo "$arg_name" | grep -qiE "$SAFE_PATTERNS"; then
      echo "- 💡 build.args contient \`$arg_name\` — variable non sensible" >> "$REPORT"
      has_safe=1
      SUMMARY_BUILD_ARGS_SAFE=$((SUMMARY_BUILD_ARGS_SAFE + 1))
    else
      echo "- 💡 build.args contient \`$arg_name\` — à vérifier" >> "$REPORT"
    fi
  done <<< "$args_lines"

  # Fallback if we couldn't parse individual args
  if [ "$has_secret" -eq 0 ] && [ "$has_safe" -eq 0 ]; then
    echo "- 💡 build.args détecté — vérifier manuellement si des secrets sont exposés" >> "$REPORT"
  fi

  echo "" >> "$REPORT"
done
