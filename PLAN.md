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

### On the agent: one SBOM per image, per host

1. When a container runs an image the server has no SBOM for from that
   agent, the server asks the agent for one on the next check-in. SBOMs are
   keyed by agent and image: an agent's SBOM is trusted only for its own
   containers, and uploads must answer an outstanding request to that agent,
   which they consume. A security review found that sharing one SBOM across
   hosts let any enrolled agent overwrite another host's results; at this
   fleet size, re-inventorying shared images per host is the cheaper fix.
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

### Update jobs (phase 3)

Updates run as jobs that an agent requests, a person approves, and the host
agent executes. Agents never approve.

1. **Request.** An assistant calls the MCP tool `dockgate_update_request`
   (host, container, reason, optional Taskboard task ID), or an operator
   runs `dockgate server jobs request`. The server evaluates the update gate
   at once:
   - **denied** when the container is unknown or has no available update,
     the candidate digest is not the one the server scanned, the scan is not
     finished, the image matches an own-image prefix (those are fixed by a
     pull request instead), or the container already has an open job;
   - otherwise **pending approval**, with the gate result shown on the job:
     fixes, findings introduced at critical/high, and what remains. A
     candidate that introduces findings is held with a warning, not hidden.
2. **Approve.** A Tintwire card links to the job page in the dockgate web UI,
   which requires an OIDC sign-in (Pocket ID) and checks the signed-in user
   against an allow list. Approve and reject are POST forms with a
   per-session CSRF token. `dockgate server jobs approve|reject` on the
   server host is the fallback. Approval re-checks that the candidate digest
   is still current; a newer image supersedes the job. Pending jobs expire
   after 24 hours, approved jobs that no agent picks up after 1 hour.
3. **Dispatch.** The next report from the host's agent receives the job
   (exactly once). A dispatched job without a result after 30 minutes is
   marked lost; it is not retried automatically.
4. **Execute.** The agent recreates the container through the Engine API,
   for Compose containers too, so it needs no compose files:
   - refuse when the container changed (different ID or image reference),
     carries a dockgate label, or another container shares its network
     namespace (`network_mode: container:`);
   - pull `repository@digest` (the approved, scanned digest; registry
     credentials from the agent's Docker config) and tag it with the
     container's reference, so the tag cannot have moved since the scan;
   - rename the old container, stop it, and create the new one with the old
     name, configuration, labels, networks (with aliases), and named and
     anonymous volumes. Settings inherited from the old image (environment,
     labels, command, entrypoint, health check, exposed ports, volumes) are
     dropped so the new image's defaults apply, as `docker compose` does;
   - start it and wait for healthy (with a health check, up to 3 minutes) or
     running without restarts for 15 seconds;
   - on success remove the old container but not its volumes; on failure
     remove the new one, restore the old one's name and state, and report
     **rolled back** with the new container's last log lines.
5. **Audit.** Every transition is stored with its actor (MCP client, OIDC
   user, CLI, agent) and time; the job page and `dockgate_job_status` show
   the history and the agent's step log.

Container settings that cannot be carried over through the Engine API (for
example a legacy `--link` to a container that no longer exists) fail the
job before anything is stopped.

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

As built in phase 1:

- The server is its own CA (ECDSA P-256, created in the data directory on
  first start) and issues its agent-facing TLS certificate for the
  configured host names. It sends the CA certificate with its chain.
- A join token is `dgt1.<id>.<secret>.<ca-pin>`: a single-use, expiring
  credential (only its SHA-256 is stored) plus the SHA-256 of the CA's
  public key. The agent trusts the server on first contact only if the chain
  contains a CA with that pin which issued the server certificate.
- The agent generates its key locally and sends a CSR; the key never leaves
  the host. The server pins the key's SubjectPublicKeyInfo hash.
- Client certificates last 90 days and renew over mTLS 30 days before
  expiry, with the same key. A renewal CSR for a different key is refused.
- Agents are named by the token (usually the host name). A second agent with
  an active agent's name needs a `-replace` token, which re-keys the existing
  agent and keeps its ID and history.

`go.michaelspost.com/gatekit` was considered: its concerns are network
handshake fingerprinting, Gatehub sync and connection limits, none of which
apply to enrollment, so it is not used.

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
   current tool on one host. *Code complete; not yet deployed. Still to do:
   an Ansible role for agents, and a first host running next to the old
   tool.*
2. **Scanning.** Agent SBOM generation with a digest-pinned Trivy image;
   server-side database and matching; findings rows; re-match on database
   update; ignore list; alerts on new fixable findings. Validate SBOM results
   against direct image scans. *Built. A prototype on real images gave
   identical findings for SBOM matching and direct scans (30/30 and 220/220).
   Trivy is pinned to 0.74.0: image by digest on agents, binary by checksum
   on the server.*
3. **UI and updates.** OIDC sign-in, job queue with approval, update gate,
   audit log (see [Update jobs](#update-jobs-phase-3)). Fleet and host views
   follow.
4. **Policy (audit).** Rules, exception labels, violation reporting.
5. **Migration.** Move every host over, then retire the old tool and its
   notification relay.
6. **Optional enforcement.** Authorization plugin, per host, fail-open.

## Open questions

- Large images take minutes to inventory (one multi-gigabyte image took
  about 4.5 minutes) because Trivy exports the image from the daemon. The
  agent works through requests one at a time in the background so reports
  are not delayed; the server asks for at most two images per report.
- Ship the agent as a container (needs the socket mounted) or a systemd
  service (simpler socket access, Ansible-native)?
