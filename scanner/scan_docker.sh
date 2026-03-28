#!/bin/bash
# Arguments: $1=PROJECTS_DIR $2=REPORT_FILE
SCAN_DIR="$1"
REPORT="$2"

echo "## Analyse sécurité Docker" >> "$REPORT"
echo "" >> "$REPORT"

# --- Dockerfiles ---
find "$SCAN_DIR" -maxdepth 4 \( -name "Dockerfile" -o -name "Dockerfile.*" \) -not -path "*/.git/*" | while read df; do
  proj=$(echo "$df" | sed "s|$SCAN_DIR/||")
  echo "### Dockerfile: \`$proj\`" >> "$REPORT"

  # Secrets dans ARG/ENV
  secrets_found=$(grep -n "ARG\|ENV" "$df" | grep -i "token\|secret\|key\|password\|api_key\|database_url\|openai\|anthropic\|mistral\|groq\|s3\|aws\|ovh\|smtp" 2>/dev/null)
  if [ -n "$secrets_found" ]; then
    log_warning "Secrets potentiels dans $proj"
    echo "- ⚠️ **Secrets dans ARG/ENV** (exposés pendant le build)" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "$secrets_found" >> "$REPORT"
    echo '```' >> "$REPORT"
  fi

  # Fichiers sensibles copiés
  sensitive_copy=$(grep -n "COPY\|ADD" "$df" | grep -i "\.env\|\.npmrc\|credentials\|\.ssh\|\.pypirc\|\.aws" 2>/dev/null)
  if [ -n "$sensitive_copy" ]; then
    log_warning "Fichiers sensibles copiés dans $proj"
    echo "- ⚠️ **Fichiers sensibles copiés dans le build**" >> "$REPORT"
  fi

  # Multi-stage
  stages=$(grep -c "^FROM " "$df")
  if [ "$stages" -gt 1 ]; then
    echo "- ✅ Multi-stage build ($stages stages)" >> "$REPORT"
  else
    echo "- ⚠️ Single-stage build" >> "$REPORT"
  fi

  # User non-root
  if grep -q "^USER " "$df"; then
    echo "- ✅ User non-root défini" >> "$REPORT"
  else
    echo "- ⚠️ Pas de USER — conteneur tourne en root" >> "$REPORT"
  fi

  # pip/npm install sans lockfile
  if grep -q "pip install" "$df" && ! grep -q "requirements\|pyproject\|poetry\|uv\|pip-compile" "$df"; then
    echo "- ⚠️ pip install direct sans lockfile" >> "$REPORT"
  fi

  echo "" >> "$REPORT"
done

# --- docker-compose : secrets dans build.args ---
find "$SCAN_DIR" -maxdepth 4 \( -name "docker-compose*.yml" -o -name "docker-compose*.yaml" \) -not -path "*/.git/*" | while read dc; do
  proj=$(echo "$dc" | sed "s|$SCAN_DIR/||")

  build_args=$(grep -A5 "build:" "$dc" | grep -i "args" 2>/dev/null)
  if [ -n "$build_args" ]; then
    echo "### Compose: \`$proj\`" >> "$REPORT"
    echo "- ⚠️ **build.args détecté** — secrets potentiellement exposés pendant le build" >> "$REPORT"
    echo "" >> "$REPORT"
  fi
done
