# dockgate

dockgate watches a small fleet of Docker hosts from one place. An agent on
each host reports containers, images and available image updates to a
central server over mutual TLS, and inventories each image for
vulnerability scanning. The server exports per-host checks to Fleetglass and
can alert through Tintwire. Updates run as gated jobs: an assistant or
operator requests one, a person approves it in the web UI, and the host's
agent recreates the container. Policy auditing comes later; see
[PLAN.md](PLAN.md).

Status: phases 1 (reporting) and 2 (vulnerability scanning), and phase 3's
update jobs with the approval UI. Fleet and host views are not built yet.

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

- Vulnerability scanning splits the work. For each image the server has no
  SBOM for, the agent runs Trivy in a throwaway container (pinned by digest,
  no network, read-only root filesystem, no capabilities) to list the image's
  packages as a CycloneDX SBOM, and uploads it. The server keeps the
  vulnerability database, matches every SBOM against it with a pinned Trivy
  binary, and re-matches the whole fleet when the database updates, without
  contacting any host. Findings are stored per package.
- An agent's SBOM is trusted only for that agent's own containers. The server
  accepts an upload only for an image it asked that agent for and still
  awaits, and consumes the request, so an agent can neither push unsolicited
  SBOMs nor replace another host's. An image shared by several hosts is
  therefore inventoried once per host.
- The vulnerability check reports `unknown` until a host's images are
  scanned, and `warn` while only some are, so a stalled or disabled scanner
  never looks like a clean host.
- The server also inventories images straight from their registries, with
  network access the agents' scanner does not have. For every available
  update it scans the candidate image (the new digest, for the host's
  platform) and compares critical and high findings with the running image:
  an update is *actionable* when it fixes some without introducing a new
  critical one. When an agent cannot inventory an image (for example one
  whose JAR files need Trivy's Java database), the server inventories the
  same digest from the registry instead.
- Alerts go out once per repository, vulnerability and package when a
  fixable finding at an alerting severity (default critical and high) first
  appears. The first run records existing findings as a baseline and sends
  one summary instead of hundreds of alerts.

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
sudo -u dockgate dockgate server vulns [-host bravo] [-all]
sudo -u dockgate dockgate server ignore add -vuln CVE-2026-1234 [-package openssl] [-image postgres] -reason "..." [-ttl 720h]
sudo -u dockgate dockgate server ignore list
sudo -u dockgate dockgate server ignore rm ID
```

Ignore rules need a reason and expire (30 days by default); an expired rule
stops hiding its findings.

Tokens are valid for one hour by default (`-ttl`). Use `-replace` to re-key
an existing agent, for example after rebuilding its host.

## Agent

```sh
dockgate agent enroll -server https://dockgate.example.net:8443 -token dgt1....
dockgate agent run
```

The agent keeps its key and certificates in `-state-dir`
(default `/var/lib/dockgate-agent`). It needs access to the Docker socket,
which is equivalent to root on the host. `-jobs=false` keeps a host
report-only.

## Update jobs

An update job moves one container to the update candidate the server has
scanned. It is requested over MCP (`dockgate_update_request`) or with
`dockgate server jobs request -host H -container C -reason "..."`.

1. **Gate.** The request is denied when there is no available update, the
   candidate scan is missing or failed, the container is not running, the
   image matches `-own-image-prefixes` (fix those with a pull request), or the
   container already has an open job. Otherwise the job waits for approval,
   with the critical/high findings the update fixes, introduces and leaves.
   A candidate that introduces findings is flagged, not hidden.
2. **Approve.** A Tintwire card links to the job page. Approving needs an
   OIDC sign-in by an allowed email or group, and re-checks that the
   candidate is still current. `dockgate server jobs approve|reject JOB_ID`
   on the server host does the same. Nobody approving within 24 hours
   expires the job.
3. **Run.** The host's agent receives the approved job once, with its next
   report. It pulls `repository@digest`, tags it with the container's
   reference, renames and stops the old container, creates the new one with
   the same configuration, labels, networks and volumes (dropping settings
   that only echoed the old image's defaults), and waits for it to be healthy
   or to stay up. If that fails, it removes the new container and restores
   the old one. Compose containers are recreated the same way, so the agent
   needs no compose files.

Every step is recorded with who did it; `dockgate_job_status`, the job page
and `dockgate server jobs show JOB_ID` show the history and the agent's step
log.

### Web UI

```sh
dockgate server run -web-listen 127.0.0.1:8099 -web-url https://dockgate.example \
  -oidc-issuer https://id.example -oidc-client-id dockgate -oidc-allowed-emails you@example.com
```

with the client secret in `DOCKGATE_OIDC_CLIENT_SECRET`. Register the OIDC
client with the redirect URL `<web-url>/auth/callback`. The UI refuses to
start without OIDC and an allow list. Serve it behind an HTTPS proxy.

## Taskboard tasks for actionable updates

With `-taskboard-url` (and a dedicated agent credential in
`DOCKGATE_TASKBOARD_TOKEN`), the server files one Taskboard task per host and
container whose update is actionable, most critical fixes first, up to
`-taskboard-max-open` (default 5). Tasks are agent-lane work routed by
`-taskboard-requirements` (default `runner:local`), with the impact, digests
and fix policy in the summary and a four-step checklist: re-check (including
release notes), request the update job, wait for approval and the result,
verify. Images matching `-own-image-prefixes` are fixed by pull request rather
than pull and recreate. The summary ends with a `dockgate-task: {...}` JSON
line (host, container, image, candidate digest, `fix` of `update_job` or
`pull_request`) for workers. BuildKit builder containers that `docker buildx`
runs (`buildx_buildkit_*`) are scanned but never get tasks or jobs. Exited, dead,
and never-started containers do not generate automatic update tasks.

While a task is unclaimed dockgate refreshes it when the candidate image
changes and cancels it with a "Resolved" note when the update stops being
needed. Once an agent claims it, dockgate only reads it. A task a person or
worker completed is not refiled until a newer image appears. Cancelling a task
dismisses that host/container even when a newer image appears; explicitly reopen
the same task to resume tracking. Producer cancellation with a "Resolved" note
does not suppress a future actionable update. This needs a
Taskboard that lets producers maintain their unclaimed tasks, and the
credential's policy must allow the requirement token and `task:sensitive`.

## MCP for agents

`dockgate server run -mcp-listen 127.0.0.1:8098 -mcp-token-file /etc/dockgate/mcp.token`
serves MCP tools over Streamable HTTP at `/mcp`. All are read-only except
`dockgate_update_request`, which only files a job that a person must
approve:

| Tool | Returns |
| --- | --- |
| `dockgate_fleet_status` | per host: reporting state, container health, pending updates, fixable critical/high counts, scan coverage |
| `dockgate_host_containers` | one host's containers with image, health, compose project and working directory, update status and fixable counts |
| `dockgate_pending_updates` | containers whose tag points to a newer image, with digests |
| `dockgate_vulnerabilities` | findings after ignore rules (default: fixable critical and high), with a limit |
| `dockgate_find_vulnerability` | which hosts and containers have a given CVE |
| `dockgate_ignores_list` | active ignore rules |
| `dockgate_update_impact` | for each available update: critical/high findings it fixes and introduces, and whether it is actionable |
| `dockgate_scan_failures` | containers whose image could not be inventoried or matched |
| `dockgate_update_request` | files an update job; returns it pending approval (with `approval_url`) or denied with the reason |
| `dockgate_job_status` | one job: state, gate, decision, agent step log and history |
| `dockgate_jobs` | recent jobs, optionally for one host or only open ones |

Every request needs `Authorization: Bearer <token>`. The listener is meant for
loopback behind an HTTPS proxy that admits only your MCP gateway; the SDK's
localhost Host check is disabled for that reason, so never expose the
listener directly. Approving jobs, enrollment, tokens, revocation and
settings are not available over MCP.

## Fleetglass checks

For each agent, filed under source `dockgate` with the agent's name as host:

| Kind | Name | Status |
| --- | --- | --- |
| `agent_health` | `checkin` | `bad` when no report for five report intervals; `warn` on collection errors |
| `container_updates` | `pending_updates` | `warn` when any container's tag points at a newer image |
| `container_health` | `containers` | `bad` when a container is unhealthy or restarting |
| `container_vulnerabilities` | `fixable` | `warn` with a fixable critical or high finding, or when an image could not be scanned |

## Build and test

```sh
go build ./...
go test -race ./...
go vet ./...
```

## Deploy

```sh
cd ansible
cp inventory.example inventory                         # then set the real hosts
cp host_vars/example.yml.example host_vars/<host>.yml  # agent hosts, Fleetglass URL
ansible-playbook playbook.yml                          # server
ansible-playbook agent.yml                             # agents
```

`playbook.yml` builds locally, installs a hardened systemd unit, and waits until
`/version` reports the deployed commit.

`agent.yml` installs `dockgate-agent.service` on each host in
`dockgate_agents`, running as a dedicated user in the `docker` group. On a host
that is not enrolled yet it mints a 10-minute join token on the server host and
enrolls with it straight away, so tokens never touch the inventory. It then
waits until the server lists a fresh report from that agent at the deployed
version. Set `dockgate_server_url` and `dockgate_server_inventory_host` for the
agent hosts, and `dockgate_agent_goarch=arm64` where needed.

Registry credentials for update checks go in
`/etc/dockgate-agent/docker/config.json` on the agent host.

## License

MIT. See [LICENSE](LICENSE).
