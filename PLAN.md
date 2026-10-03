# dockgate plan

dockgate watches a small fleet of Docker hosts from one place. A lightweight
agent on each host reports containers, images, update availability and
vulnerability scans to a central server. The server shows the fleet, gates
image updates on scan results, and audits what is allowed to run.

It replaces the parts of a general-purpose Docker UI that a homelab operator
actually uses, and deliberately leaves out the rest.

## Goals

- One view of every container on every host: state, health, image digest,
  restarts, resource use.
- Detect available image updates without pulling, by comparing the running
  digest with the registry's current digest for the tag.
- Scan each image digest for vulnerabilities, once, and rescan when the
  vulnerability database changes.
- Update a container or Compose service from the central server, **gated** on
  the scan of the new image.
- Report containers that break policy (registry, tag pinning, privileged,
  Docker socket mounts, host networking).
- Feed summary checks to an external fleet monitor and alerts to a
  notification service.

## Non-goals

- Interactive exec, terminals, file browsing or log streaming.
- Compose editing, Git-driven deployment or stack orchestration.
- Multi-tenant users and RBAC beyond a single operator role.
- Managing Swarm or Kubernetes.

Leaving these out keeps the agent's command surface small, which is the main
security property of the design.

## Architecture

```
        ┌──────────────── dockgate server ────────────────┐
        │ SQLite · web UI (OIDC) · MCP · job queue        │
        │ policy engine · scan diff · exporters           │
        └──────▲────────────────────────────▲─────────────┘
               │ HTTPS, mTLS, agent-initiated│
       ┌───────┴───────┐             ┌──────┴────────┐
       │ dockgate agent│    ...      │ dockgate agent│
       │ Docker socket │             │ Docker socket │
       │ scanner       │             │ scanner       │
       └───────────────┘             └───────────────┘
```

One Go module, one binary, two subcommands: `dockgate server` and
`dockgate agent`.

### Agent

- Connects **outbound only**. It never listens on a network port, so hosts
  behind NAT work and there is no remote Docker API to protect.
- Reads the local Docker socket: containers, images, events, stats, Compose
  labels.
- Checks registries for updates with a manifest `HEAD` per tag, using
  credentials configured on the agent. Never pulls just to check.
- Scans with Trivy (and optionally Grype) per image digest, caches results
  locally keyed by digest and scanner database version.
- Polls the server for jobs on each check-in and executes only allow-listed
  operations:
  - `pull` an image reference;
  - `recreate` a container with an updated image, preserving its config;
  - `compose-update` a service (`docker compose pull` then `up -d`) for
    containers carrying Compose labels;
  - `restart` a container.
- Refuses anything else. There is no generic command or exec channel.

### Server

- Go, SQLite (WAL, local disk only), standard-library HTTP.
- Browser sign-in through OIDC (`go.michaelspost.com/oidcrp`). There is no
  unauthenticated mode.
- MCP endpoint for agents and assistants (`go.michaelspost.com/mcpkit`):
  read tools for fleet state; update requests go through the same gate and
  confirmation as the UI.
- Notifications through Tintwire (`go.michaelspost.com/tintwire-go`).
- Exports summary checks to a fleet monitor over its ingest API.
- Audit log of every job: who requested it, gate decision, agent result.

## Gate features

### 1. Update gate

When an update is requested (or found, if auto-update is enabled for a
container):

1. The agent pulls the candidate image and scans it.
2. The server diffs the candidate scan against the running image's scan.
3. Policy decides:
   - **allow** when the candidate introduces no new findings at or above the
     configured severity;
   - **hold for approval** when it does, showing the new CVEs;
   - **deny** when a rule says so (for example a known-bad digest).
4. Only an allowed or approved job reaches `recreate` / `compose-update`.

Comparing against the running image matters: an update that fixes ten CVEs
and adds none should pass even if the image still has old findings.

### 2. Policy gate

Rules evaluated against every running container, for example:

- image registry must be on an allow list;
- tags must be pinned or digest-qualified (no bare `:latest`);
- no `--privileged`, Docker socket mounts or host networking unless the
  container carries an explicit exception label.

Phase one is **audit mode**: violations are reported, never blocked. A later,
per-host opt-in mode can enforce at the daemon with a Docker authorization
plugin. Enforcement must fail open and be removable without the server,
because an unavailable authorization plugin can otherwise block every Docker
API call on that host.

### 3. Pinned agent enrollment

- An operator creates a one-time enrollment token on the server.
- The agent generates a key pair, enrolls with the token, and the server pins
  the agent's public key fingerprint and issues a client certificate.
- Every check-in uses mTLS with that certificate; the server rejects unknown
  or revoked fingerprints.
- Re-keying or moving an agent requires a new enrollment.

This mirrors the fingerprint pinning used by the operator's other gates and
should reuse `go.michaelspost.com/gatekit` where its concerns fit.

## Data model (initial)

- `agents` — id, name, fingerprint, cert serial, last seen, version, status.
- `containers` — agent, container id, name, image ref, digest, state, health,
  compose project/service, labels, last seen.
- `images` — digest, refs, size, created.
- `update_checks` — container, current digest, remote digest, checked at.
- `scans` — digest, scanner, scanner db version, counts by severity,
  findings (compressed JSON), scanned at.
- `policy_violations` — container, rule, first/last seen, acknowledged.
- `jobs` — kind, target, requested by, gate decision, approval, state,
  result, timestamps.
- `enrollment_tokens` — hash, expires, used by.

## Phases

1. **Reporting.** Agent and server with enrollment and mTLS; container and
   image inventory; update checks; fleet monitor export. Run alongside the
   current tool on one host.
2. **Scanning.** Trivy integration, per-digest cache, severity summaries,
   alerts for new criticals.
3. **UI and updates.** OIDC sign-in, fleet and host views, job queue,
   update gate, audit log.
4. **Policy (audit).** Rules, exception labels, violation reporting.
5. **Migration.** Move every host over, then retire the old tool and its
   notification relay.
6. **Optional enforcement.** Authorization plugin, per host, fail-open.

## Open questions

- Run the scanner as an embedded library, a bundled binary, or a sidecar
  container? A binary keeps the agent image small and the scanner updatable.
- Share one vulnerability database mirror for all agents to avoid every host
  downloading it?
- Ship the agent as a container (needs the socket mounted) or a systemd
  service (simpler socket access, Ansible-native)?
