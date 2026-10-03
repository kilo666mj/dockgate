#!/usr/bin/env bash
# Turn a fresh copy of go-service-template into a named service.
#
#   scripts/rename.sh <name> [module-path]
#
# <name> is the binary, systemd unit and user name (lowercase, digits and
# hyphens). The module path defaults to github.com/kilo666mj/<name>.
set -euo pipefail

name=${1:?usage: scripts/rename.sh <name> [module-path]}
module=${2:-github.com/kilo666mj/$name}

if [[ ! $name =~ ^[a-z][a-z0-9-]*$ ]]; then
	echo "name must match ^[a-z][a-z0-9-]*\$" >&2
	exit 1
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

ident=${name//-/_}                           # Ansible variable prefix and group
env_prefix=$(tr '[:lower:]' '[:upper:]' <<<"$ident")

mapfile -t files < <(git ls-files 2>/dev/null || find . -type f -not -path './.git/*' | sed 's|^\./||')

for f in "${files[@]}"; do
	[ -f "$f" ] || continue
	case "$f" in scripts/rename.sh | scripts/test-rename.sh | .github/workflows/template.yml) continue ;; esac
	sed -i \
		-e "s|github.com/kilo666mj/go-service-template|$module|g" \
		-e "s|SERVICENAME|$env_prefix|g" \
		-e "s|^\[servicename\]|[$ident]|" \
		-e "s|hosts: servicename$|hosts: $ident|" \
		-e "s|servicename_|${ident}_|g" \
		-e "s|servicename|$name|g" \
		"$f"
done

mv ansible/group_vars/servicename "ansible/group_vars/$ident"
for f in ansible/templates/servicename.*; do
	mv "$f" "${f/servicename/$name}"
done

cat >README.md <<README
# $name

TODO: one paragraph on what $name does and who uses it.

## Build and test

\`\`\`sh
go build ./...
go test -race ./...
go vet ./...
\`\`\`

## Deploy

\`\`\`sh
cd ansible
cp inventory.example inventory   # then set the real host
ansible-playbook playbook.yml
\`\`\`

The playbook builds locally, installs a hardened systemd unit, and waits until
\`/version\` reports the deployed commit.
README

rm -f scripts/rename.sh scripts/test-rename.sh .github/workflows/template.yml
rmdir scripts 2>/dev/null || true
echo "Renamed to $name ($module). Review README.md, AGENTS.md and ansible/group_vars/$ident/vars.yml."
