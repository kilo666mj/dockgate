# dockgate

dockgate watches a small fleet of Docker hosts from one place. An agent on
each host reports containers, images and available image updates to a
central server over mutual TLS. The server exports per-host checks to
Fleetglass. Later phases add vulnerability scanning, gated updates and
policy auditing; see [PLAN.md](PLAN.md).

Status: phase 1 (reporting). There is no web UI yet.

## How it works

- `dockgate server run` serves the agent API on its own TLS port and keeps
  state in SQLite. It is its own certificate authority: on first start it
  creates a CA in the data directory and issues itself a server certificate
  for the names in `-agent-hosts`.
- `dockgate agent run` reads the local Docker socket and reports every minute.
  It only connects outbound and never listens on a port.
- Agents enroll once with a single-use join token. The token carries the CA's
  public key pin, so the agent can verify the server on first contact. The
  server pins each agent's key; certificates renew automatically with the
  same key, and `dockgate server revoke` cuts an agent off.
- Update checks compare each container's local repository digest with the
  digest its tag resolves to now, using manifest `HEAD` requests (no pulls,
  no Docker Hub rate-limit cost). Each tag is checked at most every
  `-update-interval` (default 6h). Registry credentials come from the agent's
  Docker client configuration (`$DOCKER_CONFIG/config.json`).

The agent API uses mutual TLS. Expose its port directly; a proxy that
terminates TLS in front of it breaks agent authentication.

## Server

```sh
dockgate server run \
  -data-dir /var/lib/dockgate \
  -agent-hosts dockgate.example.net \
  -fleetglass-url https://fleetglass.example.net   # token in DOCKGATE_FLEETGLASS_TOKEN
```

Every flag has a `DOCKGATE_*` environment equivalent; run
`dockgate server run -h`. The health endpoints (`/healthz`, `/readyz`,
`/version`) listen on `127.0.0.1:8080` by default.

Administration commands open the same database, so run them as the service
user:

```sh
sudo -u dockgate dockgate server token -name bravo   # prints a join token
sudo -u dockgate dockgate server agents
sudo -u dockgate dockgate server tokens
sudo -u dockgate dockgate server revoke bravo
```

Tokens are valid for one hour by default (`-ttl`). Use `-replace` to re-key
an existing agent, for example after rebuilding its host.

## Agent

```sh
dockgate agent enroll -server https://dockgate.example.net:8443 -token dgt1....
dockgate agent run
```

The agent keeps its key and certificates in `-state-dir`
(default `/var/lib/dockgate-agent`). It needs access to the Docker socket,
which is equivalent to root on the host.

## Fleetglass checks

For each agent, filed under source `dockgate` with the agent's name as host:

| Kind | Name | Status |
| --- | --- | --- |
| `agent_health` | `checkin` | `bad` when no report for five report intervals; `warn` on collection errors |
| `container_updates` | `pending_updates` | `warn` when any container's tag points at a newer image |
| `container_health` | `containers` | `bad` when a container is unhealthy or restarting |

## Build and test

```sh
go build ./...
go test -race ./...
go vet ./...
```

## Deploy the server

```sh
cd ansible
cp inventory.example inventory                         # then set the real host
cp host_vars/example.yml.example host_vars/<host>.yml  # agent hosts, Fleetglass URL
ansible-playbook playbook.yml
```

The playbook builds locally, installs a hardened systemd unit, and waits until
`/version` reports the deployed commit.

## License

MIT. See [LICENSE](LICENSE).
