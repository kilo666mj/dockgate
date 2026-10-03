# AGENTS.md - servicename

After Go changes, run:

```sh
gofmt -w .
go test -race ./...
go vet ./...
```

Keep this repository free of private DNS names, internal zones, private
addresses, credentials and deployment inventory. Real values belong in the
gitignored `ansible/inventory`, `ansible/host_vars/*.yml` or
`ansible/group_vars/*/secret.yml`, or in an Ansible Vault.

Deploy with `ansible/playbook.yml`, which verifies that `/version` reports the
deployed commit. Run `ansible-playbook --syntax-check playbook.yml` after
playbook changes.

Use the shared modules in `docs/kits.md` for MCP, sign-in, notifications and
web push rather than re-implementing them. `errcheck` is blocking: handle or
explicitly discard every error, and preserve the primary error when deferred
cleanup also fails.
