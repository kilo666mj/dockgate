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
- Generates a software bill of materials (SBOM) once per new image digest
  and sends it to the server, which does the vulnerability matching. See
  [Vulnerability scanning](#vulnerability-scanning).
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

## Vulnerability scanning

The agent inventories each image; the server finds the vulnerabilities. The
split keeps the vulnerability database in one place and lets the server
rescan the whole fleet without touching any host.

### On the agent: one SBOM per digest

1. When a container runs an image digest the server has no SBOM for, the
   server asks the agent for one on the next check-in. The same digest on
   several hosts is inventoried once.
2. The agent runs Trivy in a short-lived container against the local image
   and produces a CycloneDX SBOM (`trivy image --format cyclonedx`). Nothing
   is pulled or exported off the host.
3. The scanner image is pinned **by digest** (`aquasec/trivy@sha256:...`),
   not by tag, and bumped deliberately. A tag can be repointed upstream, and
   the scanner has Docker socket access.
4. The agent uploads the SBOM, compressed, keyed by image digest.

Mounting the socket `:ro` does not make the Docker API read-only; it only
stops the file itself being replaced. Any process with the socket has full
Docker access, which is why the scanner image is pinned. Generating an SBOM
needs no vulnerability database, so the container should run with
`--network none`; confirm the exact Trivy flags for that in phase 2.

### On the server: matching against one database

- The server keeps the Trivy vulnerability database and refreshes it on a
  schedule. Agents never download it.
- It matches each stored SBOM (`trivy sbom`) and stores the results.
- When the database updates, the server re-matches every stored SBOM. New
  CVEs for running images appear without any agent work.
- Grype is optional and off by default. When enabled it also runs
  server-side against the same SBOMs, and findings are merged by
  vulnerability ID and package so a CVE reported by both counts once.

SBOM-based matching relies on the SBOM recording OS and package details
accurately. Phase 2 should compare SBOM results with a direct
`trivy image` scan on a few real images before relying on it.

### Findings

Findings are stored as rows, not as an opaque scan blob:
vulnerability ID, package, installed version, fixed version (if any),
severity, and which scanners reported it. Rows make the update gate's diff
a query ("the candidate adds CVE-X and fixes 12 others") and make
cross-fleet questions ("which hosts run anything with CVE-Y?") cheap.

### Triggers

- a new image digest appears on any host;
- the vulnerability database updates (server-only re-match);
- a candidate image arrives for the update gate (the agent pulls it,
  generates its SBOM, and the server matches it before deciding).

### Noise control

- Alert only on new findings at or above a configured severity that have a
  fix available. Everything is still recorded and visible.
- An ignore list scoped to a vulnerability ID, optionally a package or image
  repository, with a required reason and an expiry date. Expired entries
  alert again.
- Alerts fire on change (a new finding, a fix becoming available), not on
  every rescan.

## Gate features

### 1. Update gate

When an update is requested (or found, if auto-update is enabled for a
container):

1. The agent pulls the candidate image and sends its SBOM.
2. The server matches it and diffs the candidate's findings against the
   running image's findings.
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
- `sboms` — digest, format, scanner version, compressed document, created.
- `scans` — digest, scanner, scanner db version, counts by severity,
  scanned at.
- `findings` — scan, vulnerability ID, package, installed version, fixed
  version, severity.
- `vuln_ignores` — vulnerability ID, optional package/repository scope,
  reason, expires, created by.
- `policy_violations` — container, rule, first/last seen, acknowledged.
- `jobs` — kind, target, requested by, gate decision, approval, state,
  result, timestamps.
- `enrollment_tokens` — hash, expires, used by.

## Phases

1. **Reporting.** Agent and server with enrollment and mTLS; container and
   image inventory; update checks; fleet monitor export. Run alongside the
   current tool on one host.
2. **Scanning.** Agent SBOM generation with a digest-pinned Trivy image;
   server-side database and matching; findings rows; re-match on database
   update; ignore list; alerts on new fixable findings. Validate SBOM results
   against direct image scans.
3. **UI and updates.** OIDC sign-in, fleet and host views, job queue,
   update gate, audit log.
4. **Policy (audit).** Rules, exception labels, violation reporting.
5. **Migration.** Move every host over, then retire the old tool and its
   notification relay.
6. **Optional enforcement.** Authorization plugin, per host, fail-open.

## Open questions

- Run the server's Trivy as a bundled binary or call it as a container? The
  agent side is settled: a short-lived, digest-pinned container.
- Ship the agent as a container (needs the socket mounted) or a systemd
  service (simpler socket access, Ansible-native)?
