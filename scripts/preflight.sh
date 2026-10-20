#!/bin/bash
# Preflight for the Claude Code pipeline. Run from the repo root: bash scripts/preflight.sh
# Add --full to also compile and run the unit tests (slower).
pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; fail=$((fail+1)); }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

echo "== Location =="
check "inside the repo root (pom.xml and mvnw present)" '[ -f pom.xml ] && [ -x ./mvnw ]'
check "repo is not nested (pom.xml at git top level)" '[ "$(git rev-parse --show-toplevel)" = "$(pwd)" ]'

echo "== Toolchain =="
JV=$(java -version 2>&1 | head -n1)
echo "      java: $JV"
check "java is 25" 'java -version 2>&1 | grep -q "\"25"'
check "JAVA_HOME is set" '[ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ]'
check "pom targets Java 25" 'grep -q "<java.version>25</java.version>" pom.xml'
check "pom uses Spring Boot 4.1.x" 'grep -Eq "<version>4\.1\.[0-9]+</version>" pom.xml'
check "docker daemon is running" 'docker info'
check "docker compose available" 'docker compose version'
check "jq installed (hooks need it)" 'command -v jq'
check "pandoc installed (PRD conversion)" 'command -v pandoc'
check "gh installed and logged in" 'gh auth status'

echo "== Git =="
check "on branch main" '[ "$(git branch --show-current)" = "main" ]'
check "working tree clean" '[ -z "$(git status --porcelain)" ]'
check "origin remote set" 'git remote get-url origin'
git fetch -q origin 2>/dev/null
check "main matches origin/main" '[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ]'

echo "== Secrets =="
touch .env.preflight.tmp .env
check ".env is gitignored" 'git check-ignore -q .env'
check ".env.* is gitignored" 'git check-ignore -q .env.preflight.tmp'
rm -f .env.preflight.tmp
[ -s .env ] || rm -f .env
check "no .env tracked in git" '[ -z "$(git ls-files | grep -E "(^|/)\.env($|\.)" | grep -v "\.env\.example$")" ]'
check ".env.example is tracked" 'git ls-files --error-unmatch .env.example'
check "no obvious secrets committed" '! git grep -nEi "(password|secret|api[_-]?key)[[:space:]]*[=:][[:space:]]*[A-Za-z0-9/+_-]{12,}" -- ":!*.md" ":!.env.example" ":!src/test" ":!mvnw" ":!mvnw.cmd"'

echo "== Pipeline files =="
for f in CLAUDE.md docs/BUILD_ORDER.md docs/PRD.md .claude/settings.json \
         .claude/skills/build-slice/SKILL.md \
         .claude/agents/test-engineer.md .claude/agents/reviewer.md \
         .claude/agents/security-reviewer.md .claude/agents/devops.md \
         .claude/hooks/guard.sh .claude/hooks/check-done.sh; do
  check "$f exists and is not empty" "[ -s '$f' ]"
done
check "hooks are executable" '[ -x .claude/hooks/guard.sh ] && [ -x .claude/hooks/check-done.sh ]'
check "settings.json is valid JSON" 'jq empty .claude/settings.json'
check "PRD looks complete (has section 17)" 'grep -q "Acceptance Criteria" docs/PRD.md'
for a in test-engineer reviewer security-reviewer devops; do
  check "agent $a has name and description" "head -n1 .claude/agents/$a.md | grep -q '^---' && grep -q '^name: $a' .claude/agents/$a.md && grep -q '^description:' .claude/agents/$a.md"
done

echo "== Hook behavior =="
check "guard blocks reading .env" '! echo "{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"/x/.env\"}}" | .claude/hooks/guard.sh'
check "guard allows .env.example" 'echo "{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"/x/.env.example\"}}" | .claude/hooks/guard.sh'
check "guard blocks plain force push" '! echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git push --force\"}}" | .claude/hooks/guard.sh'
check "stop hook loop guard exits 0" 'echo "{\"stop_hook_active\":true}" | .claude/hooks/check-done.sh'

echo "== Local stack (optional but expected) =="
check "postgres container healthy" '[ "$(docker compose ps --format "{{.Health}}" postgres 2>/dev/null)" = "healthy" ]'
check "redis container healthy" '[ "$(docker compose ps --format "{{.Health}}" redis 2>/dev/null)" = "healthy" ]'
check "redis policy is noeviction" 'docker compose exec -T redis redis-cli config get maxmemory-policy | grep -q noeviction'

if [ "$1" = "--full" ]; then
  echo "== Build =="
  check "unit tests pass (./mvnw -q -B test)" './mvnw -q -B test'
fi

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
