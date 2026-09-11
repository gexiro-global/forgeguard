# Runner review

`forgeguard runner review` is an offline, zero-network assessment of one operator-declared
Gitea or Forgejo Actions runner's security posture. It never contacts the forge instance or
the runner, never reads a `.runner` registration file, Docker/registry credentials, repository
secrets, or environment variables, and never accepts a raw secret dump.

```bash
forgeguard runner review --snapshot runner-snapshot.json --format md,json,sarif --out reports/runner
```

## Snapshot schema

The input must validate against `forgeguard.runner-snapshot.v1`
(`forgeguard/schemas/runner-snapshot-v1.json`, packaged and installed). It is a closed schema
(`additionalProperties: false`): any field not on this list, including a field literally named
`token`, `password`, `secret`, or `cookie`, is refused before the snapshot is parsed further, and
the CLI never echoes the rejected input or the underlying validation error text.

| Field | Meaning |
|---|---|
| `schema_id` | Fixed `forgeguard.runner-snapshot.v1` |
| `product` / `server_version` | The forge instance the runner serves |
| `runner_product` / `runner_version` | `gitea-runner` or `forgejo-runner`; must match `product` |
| `instance_alias` / `runner_alias` | Non-identifying aliases, not real hostnames or usernames |
| `snapshot_at` / `provenance` | Timezone-aware timestamp and a free-text provenance note |
| `runner_scope` | `dedicated` or `shared` across repos/orgs |
| `workload_trust` | `trusted-only` or `mixed-untrusted` — drives severity, see below |
| `ephemeral` | `ephemeral`, `once`, or `persistent` registration mode |
| `execution_engine` | `docker`, `lxc`, `host`, or `plugin` (label type) |
| `privileged` | `container.privileged` |
| `docker_socket` | `not-exposed`, `host-daemon-exposed-to-job`, `dedicated-dind`, `rootless-dind`, `unknown` |
| `valid_volumes` | Declared `container.valid_volumes` allowlist (bounded to 32 entries) |
| `network` | `isolated`, `host`, or `custom` |
| `plugin_usage` | `unused` (default), `declared-experimental`, or `unknown` |

## Checks

See [CHECKS.md](CHECKS.md) for the full list (`FG-RUNNER-VERSION`, `-EXECUTION`, `-PRIVILEGED`,
`-VOLUMES`, `-DOCKER`, `-NETWORK`, `-EPHEMERAL`, `-PLUGIN`) and [UPSTREAM.md](UPSTREAM.md) for
their exact upstream citations.

## Trust-boundary severity, not a fixed vulnerability list

`workload_trust` changes severity, not applicability: the same declared posture is `WARN` under
`trusted-only` and `FAIL` under `mixed-untrusted` for `FG-RUNNER-EXECUTION` (host label),
`FG-RUNNER-PRIVILEGED`, `FG-RUNNER-VOLUMES` (broad allow pattern), `FG-RUNNER-DOCKER`
(host-daemon-exposed-to-job), and `FG-RUNNER-NETWORK` (host networking). A newer runner version
is never asserted to be more secure by itself — `FG-RUNNER-VERSION` only reports version
provenance and cites the exact, version-gated upstream facts that apply.

## No double-penalty for one root cause

When `execution_engine` is `host`, there is no container to be privileged, mount a volume into,
expose a Docker socket to, or isolate on the network — so `FG-RUNNER-PRIVILEGED`,
`FG-RUNNER-VOLUMES`, `FG-RUNNER-DOCKER`, and `FG-RUNNER-NETWORK` are `not_applicable` and only
`FG-RUNNER-EXECUTION` scores the single root cause. `FG-RUNNER-PLUGIN` is `not_applicable`
unless the declared `runner_product`/`runner_version` actually supports the plugin engine
(Forgejo Runner >= 13.1.0) and `plugin_usage` is not `unused`.

## Examples

`examples/gitea-runner-snapshot.json` and `examples/forgejo-runner-snapshot.json` are synthetic
fixtures, not evidence from a real instance.
