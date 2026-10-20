#!/bin/bash
# PreToolUse hook: block secret access, force pushes and edits to applied migrations.
input=$(cat)
tool=$(jq -r '.tool_name' <<<"$input")
file=$(jq -r '.tool_input.file_path // empty' <<<"$input")
cmd=$(jq -r '.tool_input.command // empty' <<<"$input")

deny() { echo "Blocked: $1" >&2; exit 2; }

if [ -n "$file" ]; then
  case "$(basename "$file")" in
    .env|.env.*)
      [ "$(basename "$file")" = ".env.example" ] || deny "do not read or edit .env files"
      ;;
  esac
  case "$file" in
    */db/migration/*)
      if [ "$tool" = "Edit" ] || [ "$tool" = "Write" ]; then
        if git ls-files --error-unmatch -- "$file" >/dev/null 2>&1; then
          deny "applied migrations are immutable; add a new migration instead"
        fi
      fi
      ;;
  esac
fi

if [ -n "$cmd" ]; then
  if grep -Eq '(^|[[:space:]/])\.env([[:space:]]|$)' <<<"$cmd" && ! grep -q '\.env\.example' <<<"$cmd"; then
    deny "do not touch .env files"
  fi
  if grep -Eq 'git[[:space:]]+push.*(--force|-f)([[:space:]]|$)' <<<"$cmd" && ! grep -q 'force-with-lease' <<<"$cmd"; then
    deny "no force pushes"
  fi
fi
exit 0
