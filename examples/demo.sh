#!/usr/bin/env bash
# Builds a throwaway repository with typical mistakes (all values fabricated), "fixes" them in a second commit,
# and shows that a working-tree scan looks clean while the history scan still finds them.
# Usage: bash examples/demo.sh [DIR]
set -euo pipefail
PG=${PREPUBLISH_GUARD:-prepublish-guard}
command -v "$PG" >/dev/null || { echo "prepublish-guard is not installed: run 'pip install .' first" >&2; exit 2; }
DIR=${1:-$(mktemp -d)}
rm -rf "$DIR/demo-repo" && mkdir -p "$DIR/demo-repo" && cd "$DIR/demo-repo"
export GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.com GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.com
git init -q -b main

# Fabricated values, assembled at runtime so that this script itself does not look like a leak.
TOKEN="ghp_""T8mQ2vX6kR9pL4wZ7nB3cY1dF5hJ0sGaW2e4"
KEY="AKIA""R4TX9QW2ZP7LM3KD"
cat > settings.py <<EOF
DATABASE_URL = "postgres://app:Sup3r-${RANDOM}x@db.internal:5432/app"
GITHUB_TOKEN = "${TOKEN}"
AWS_ACCESS_KEY_ID = "${KEY}"
EOF
cat > clientes.csv <<'EOF'
nombre,cedula,celular,ciudad
Ana Ruiz,1023456781,3124567890,Bogotá
Luis Mora,79845123,3159871234,Medellín
EOF
cat > README.md <<'EOF'
# demo
Data loaded from /Users/carolina/Desktop/clientes.xlsx.
Contact: carolina.mejia.dev@gmail.com
EOF
git add -A && git commit -qm "first version"

# The usual "fix": delete the file contents. The history keeps everything.
printf 'import os\nDATABASE_URL = os.environ["DATABASE_URL"]\n' > settings.py
git rm -q clientes.csv
printf '# demo\nSee docs/ for setup.\n' > README.md
printf 'MIT License\n' > LICENSE
git add -A && git commit -qm "remove secrets"

echo "--- working tree only"
set +e; "$PG" scan .; tree=$?; set -e
echo
echo "--- working tree + full history"
set +e; "$PG" scan . --history; history=$?; set -e
echo
echo "exit codes: working tree $tree (expected 0: looks clean), history $history (expected 1: leaks found)"
[ "$tree" -eq 0 ] && [ "$history" -eq 1 ]
