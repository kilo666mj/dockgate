# go-service-template

A starting point for small Go HTTP services, deployed with Ansible to a
hardened systemd unit. It carries the same baseline as the maintained
`kilo666mj` services, so a new service starts with working CI instead of
copying it from a neighbour.

## What you get

- A standard-library HTTP server with `/healthz`, `/readyz` and `/version`,
  graceful shutdown and JSON logs.
- CI: golangci-lint (including `errcheck`), `go vet`, gofmt, `go mod tidy`,
  race-enabled tests, an Ansible syntax check, and static release binaries on
  `v*` tags.
- Documentation validation pinned to the shared validator, and an issue that
  opens automatically when `main` goes red.
- Renovate for Go modules and GitHub Actions. Do not add Dependabot as well.
- An Ansible playbook that builds locally, installs the binary, environment
  file and systemd unit, then waits until `/version` reports the deployed
  commit.

## Start a service

1. Select **Use this template** on GitHub, or copy the repository.
2. Rename the placeholders:

   ```sh
   scripts/rename.sh my-service                  # module github.com/kilo666mj/my-service
   scripts/rename.sh my-service example.com/x/y  # explicit module path
   ```

   This rewrites the module path, binary, unit, Ansible variables and
   environment prefix (`MY_SERVICE_LISTEN`). It also replaces this README and
   removes the template-only files.
3. Run `go test ./...`, commit, and push.
4. Add the service's own configuration to `main.go` and
   `ansible/group_vars/<name>/vars.yml`.

## Shared libraries

Add a shared module only when the service needs its concern. See
[docs/kits.md](docs/kits.md) for what each one owns and a minimal integration.

## Verify the template

```sh
scripts/test-rename.sh
```

This renames a scratch copy, then builds it, tests it and starts it. CI runs
the same script.

## License

MIT. See [LICENSE](LICENSE).
