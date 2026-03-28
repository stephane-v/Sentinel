#!/bin/bash
# Arguments: $1=PROJECTS_DIR $2=REPORT_BODY
# NOTE: Variables inherited from sentinel.sh (sourced): EXCLUDE_DIRS, SCAN_DEPTH,
#       SUMMARY_*, L_*, COUNT_*, set_verdict, log_* functions
SCAN_DIR="$1"
REPORT="$2"
DEPTH="${SCAN_DEPTH:-4}"

SECRET_PATTERNS="TOKEN|SECRET|KEY|PASSWORD|API_KEY|DATABASE_URL|DB_|OPENAI|ANTHROPIC|MISTRAL|GROQ|SMTP|S3|AWS|OVH|CREDENTIAL"
SAFE_PATTERNS="NODE_ENV|NEXT_PUBLIC_|REACT_APP_|VITE_|PORT|HOST|DOMAIN|VERSION|BUILD_DATE|GIT_COMMIT|TZ|LANG"

_DOCKER_FIND_EXCLUDES="-not -path */.git/*"
if [ -n "${EXCLUDE_DIRS:-}" ]; then
  for _d in $(echo "$EXCLUDE_DIRS" | tr ',' ' '); do
    _d=$(echo "$_d" | xargs)
    [ -z "$_d" ] && continue
    _DOCKER_FIND_EXCLUDES="$_DOCKER_FIND_EXCLUDES -not -path */$_d/*"
  done
fi

echo "## $L_DOCKER_ANALYSIS" >> "$REPORT"
echo "" >> "$REPORT"

# --- Dockerfiles ---
# shellcheck disable=SC2086
find "$SCAN_DIR" -maxdepth "$DEPTH" \( -name "Dockerfile" -o -name "Dockerfile.*" \) $_DOCKER_FIND_EXCLUDES 2>/dev/null | while read df; do
  proj=$(echo "$df" | sed "s|$SCAN_DIR/||")
  echo "### Dockerfile: \`$proj\`" >> "$REPORT"

  secrets_found=$(grep -n "ARG\|ENV" "$df" | grep -i -E "$SECRET_PATTERNS" 2>/dev/null || true)
  if [ -n "$secrets_found" ]; then
    log_attention "Potential secrets in $proj"
    echo "- ⚠️ **$L_SECRETS_IN_ARG**" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "$secrets_found" >> "$REPORT"
    echo '```' >> "$REPORT"
    SUMMARY_SECRETS_DOCKER=$((SUMMARY_SECRETS_DOCKER + 1))
  fi

  sensitive_copy=$(grep -n "COPY\|ADD" "$df" | grep -i "\.env\|\.npmrc\|credentials\|\.ssh\|\.pypirc\|\.aws" 2>/dev/null || true)
  if [ -n "$sensitive_copy" ]; then
    log_attention "Sensitive files copied in $proj"
    echo "- ⚠️ **$L_SENSITIVE_FILES**" >> "$REPORT"
  fi

  stages=$(grep -c "^FROM " "$df" || true)
  if [ "$stages" -gt 1 ] 2>/dev/null; then
    echo "- ✅ $L_MULTI_STAGE ($stages stages)" >> "$REPORT"
  else
    log_info "Single-stage build: $proj"
    echo "- 💡 $L_SINGLE_STAGE_BUILD" >> "$REPORT"
    SUMMARY_SINGLE_STAGE=$((SUMMARY_SINGLE_STAGE + 1))
  fi

  if grep -q "^USER " "$df"; then
    echo "- ✅ $L_USER_NONROOT" >> "$REPORT"
  else
    log_info "No USER in $proj"
    echo "- 💡 $L_NO_USER_ROOT" >> "$REPORT"
    SUMMARY_NO_USER=$((SUMMARY_NO_USER + 1))
  fi

  if grep -q "pip install" "$df" && ! grep -q "requirements\|pyproject\|poetry\|uv\|pip-compile" "$df"; then
    echo "- 💡 $L_PIP_NO_LOCK" >> "$REPORT"
  fi

  echo "" >> "$REPORT"
done

# --- docker-compose: contextualized build.args ---
_extract_build_args() {
  local dc_file="$1"
  python3 -c "
import sys, json
try:
    import yaml
except ImportError:
    sys.exit(0)
try:
    with open('$dc_file') as f:
        data = yaml.safe_load(f)
    if not data or 'services' not in data:
        sys.exit(0)
    for svc_name, svc in data['services'].items():
        if not isinstance(svc, dict):
            continue
        build = svc.get('build')
        if isinstance(build, dict):
            args = build.get('args')
        else:
            continue
        if not args:
            continue
        if isinstance(args, dict):
            for k in args:
                print(k)
        elif isinstance(args, list):
            for item in args:
                print(str(item).split('=')[0])
except Exception:
    sys.exit(0)
" 2>/dev/null || true
}

# shellcheck disable=SC2086
find "$SCAN_DIR" -maxdepth "$DEPTH" \( -name "docker-compose*.yml" -o -name "docker-compose*.yaml" \) $_DOCKER_FIND_EXCLUDES 2>/dev/null | while read dc; do
  proj=$(echo "$dc" | sed "s|$SCAN_DIR/||")

  args_list=$(_extract_build_args "$dc")
  [ -z "$args_list" ] && continue

  echo "### Compose: \`$proj\`" >> "$REPORT"

  has_secret=0
  has_safe=0

  while IFS= read -r arg_name; do
    [ -z "$arg_name" ] && continue

    if echo "$arg_name" | grep -qiE "$SECRET_PATTERNS"; then
      log_attention "Secret in build.args: $arg_name in $proj"
      echo "- ⚠️ build.args: \`$arg_name\` — **$L_SECRET_EXPOSED**" >> "$REPORT"
      has_secret=1
      SUMMARY_BUILD_ARGS_SECRET=$((SUMMARY_BUILD_ARGS_SECRET + 1))
    elif echo "$arg_name" | grep -qiE "$SAFE_PATTERNS"; then
      echo "- 💡 build.args: \`$arg_name\` — $L_NON_SENSITIVE" >> "$REPORT"
      has_safe=1
      SUMMARY_BUILD_ARGS_SAFE=$((SUMMARY_BUILD_ARGS_SAFE + 1))
    else
      echo "- 💡 build.args: \`$arg_name\` — $L_TO_VERIFY" >> "$REPORT"
    fi
  done <<< "$args_list"

  if [ "$has_secret" -eq 0 ] && [ "$has_safe" -eq 0 ]; then
    echo "- 💡 $L_BUILD_ARGS_DETECTED" >> "$REPORT"
  fi

  echo "" >> "$REPORT"
done
