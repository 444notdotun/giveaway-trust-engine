#!/bin/bash
# Stop hook: if Java files changed, the unit tests must pass before Claude can stop.
input=$(cat)
if [ "$(jq -r '.stop_hook_active' <<<"$input")" = "true" ]; then
  exit 0
fi
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
export JAVA_HOME="${JAVA_HOME:-$HOME/.jdks/openjdk-25.0.2}"
export PATH="$JAVA_HOME/bin:$PATH"
if [ -z "$(git status --porcelain -- src 2>/dev/null)" ]; then
  exit 0
fi
out=$(./mvnw -q -B test 2>&1)
if [ $? -ne 0 ]; then
  echo "Unit tests are failing. Fix them before stopping:" >&2
  echo "$out" | tail -n 40 >&2
  exit 2
fi
exit 0
