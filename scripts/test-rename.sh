#!/usr/bin/env bash
# Rename a scratch copy of the template and prove the result builds, passes
# its tests and serves health checks.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'kill "${pid:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

(cd "$root" && git ls-files -z | xargs -0 cp --parents -t "$work")
cd "$work"
git init -q && git add -A

scripts/rename.sh demo-svc github.com/example/demo-svc

if leftovers=$(grep -rIl -e servicename -e SERVICENAME -e go-service-template . --exclude-dir=.git); then
	echo "placeholder left in: $leftovers" >&2
	exit 1
fi
[ -d ansible/group_vars/demo_svc ] && [ -f ansible/templates/demo-svc.service.j2 ]

gofmt -l . | (! grep .)
go vet ./...
go test ./...
go build -o demo-svc .

DEMO_SVC_LISTEN=127.0.0.1:18089 ./demo-svc &
pid=$!
for _ in $(seq 20); do
	curl -fsS http://127.0.0.1:18089/healthz >/dev/null 2>&1 && break
	sleep 0.2
done
curl -fsS http://127.0.0.1:18089/readyz
if command -v ansible-playbook >/dev/null; then
	(cd ansible && cp inventory.example inventory && ansible-playbook --syntax-check playbook.yml >/dev/null)
fi
echo "template rename OK"
