# Running in a container — inject permissions, never prompt

The primary driver for `Andy.Permissions` is running `andy-cli` / `andy-engine` **inside a container**,
where there is no human at a TTY. The model: **inject the permission rules up front** so everything the
agent needs is pre-approved and no consent prompt is ever reached. The container itself is the
blast-radius boundary; the rule engine is the consent layer.

## TL;DR

1. Write a rules file (Claude Code `permissions`-style JSON).
2. Mount it and point `ANDY_PERMISSIONS_FILE` at it (or pass the JSON inline via `ANDY_PERMISSIONS_JSON`).
3. Choose a mode with `ANDY_PERMISSION_MODE` (default `fail-closed`).

Because injected `allow` rules clear any `Ask` **before** a prompt is reached, the run proceeds with
zero approvals. Anything the injection didn't cover is denied (fail-closed) unless you opt into `bypass`.

## Environment variables

| Variable | Purpose | Precedence |
|---|---|---|
| `ANDY_PERMISSIONS_FILE` | Path to a JSON rules file to load as the highest-precedence **injected** layer. | 1 (wins) |
| `ANDY_PERMISSIONS_JSON` | Inline JSON rules (used when `ANDY_PERMISSIONS_FILE` is unset). | 2 |
| *(baked)* `/etc/andy/permissions.json` | Picked up automatically if present and neither env var is set. | 3 |
| `ANDY_PERMISSION_MODE` | The baseline mode (see below). Defaults to `fail-closed`. | — |

Only one injected source is used (no merge), so container behavior is predictable.

## Modes (`ANDY_PERMISSION_MODE`)

A mode is a **fallback shift**: it decides how an `Ask` is resolved when there is no interactive user to
consult. **No mode can ever turn a `Deny` into an `Allow`** — Deny is resolved before a prompt is reached.
In a headless/container host (`NonInteractivePermissionPrompt`), the modes resolve an `Ask` as follows:

| Value | Aliases | Ask resolves to | Use |
|---|---|---|---|
| `fail-closed` | *(default; also any unrecognized value)* | **Deny** | Unattended/CI — deny anything not pre-approved by injection. |
| `default` | | **Deny** (no TTY to ask) | The interactive baseline; headless it behaves like fail-closed. |
| `plan` | | **Deny** | Read-only: nothing requiring consent proceeds. |
| `accept-edits` | `accept_edits` | **Allow** iff every asked resource is a filesystem path, else **Deny** | Auto-approve in-scope file edits; still gate commands/network. |
| `bypass` | `yolo` | **Allow** | Trusted sandbox (e.g. `--network=none`); still honors every Deny. |

Values are case- and separator-insensitive (`-`, `_`, and space are equivalent).

The **managed** layer (admin, uncoverable Deny) is discovered automatically at
`/etc/andy/permissions.managed.json` (or `%ProgramData%\andy\permissions.managed.json` on Windows) — use it
to bake absolute denies into a base image that no injected rule or mode can loosen.

## Rules file format

Mirrors Claude Code's `settings.json#permissions` — three arrays of `tool(specifier)` strings:

```json
{
  "allow": [
    "read_file(/workspace/**)",
    "write_file(/workspace/**)",
    "execute_command(git:*)",
    "execute_command(npm:*)",
    "http_request(domain:registry.npmjs.org)"
  ],
  "ask": [],
  "deny": [
    "read_file(~/.ssh/**)",
    "execute_command(rm -rf /:*)"
  ]
}
```

- `tool` is the snake_case tool id (`read_file`, `write_file`, `execute_command`, `http_request`, …) or `*`.
- Path specifiers: `//abs` / `/abs` (absolute), `~/p` (home), `./p` or bare (relative to the working dir).
- Command specifiers: `cmd:*` is a prefix match with an argument boundary (`git:*` matches `git status` but not `gitx`).
- **Deny is absolute** — it can never be overridden by an `allow` in any layer (not even injected), so keep
  builtin/managed denies for the truly-dangerous and let injection grant what the task needs.
- Write rules **container-relative** (paths resolve against the agent's working directory inside the container).

## Docker example

```dockerfile
# ... your andy-cli/andy-engine image ...
COPY permissions.container.json /etc/andy/permissions.json
ENV ANDY_PERMISSION_MODE=fail-closed
# Agent runs headless; injected allows mean no prompts, uncovered actions are denied.
CMD ["andy", "--headless", "..."]
```

Or mount + env at run time:

```bash
docker run --rm \
  -v "$PWD/permissions.container.json:/cfg/permissions.json:ro" \
  -e ANDY_PERMISSIONS_FILE=/cfg/permissions.json \
  -e ANDY_PERMISSION_MODE=fail-closed \
  my-andy-image andy --headless "fix the failing test"
```

Trusted sandbox (let the container boundary be the only guard):

```bash
docker run --rm --network=none -e ANDY_PERMISSION_MODE=bypass my-andy-image andy --headless "..."
```

`bypass` collapses every `Ask` into `Allow` but still honors every `Deny`, so builtin denies
(`~/.ssh/**`, `rm -rf /`, …) remain in force.

## How it's wired

`AddAndyPermissions(...)` (called by andy-cli/andy-engine hosts) constructs the `FilePermissionStore`
and applies `PermissionInjectionBootstrap` at startup, which reads the env vars above and loads the
`injected` layer. The store also discovers the **managed** layer at its default path (above) unless the
host sets `PermissionStoreOptions.ManagedFilePath` to another path or `null`. The default consent provider
in a non-interactive host is `NonInteractivePermissionPrompt`, whose mode comes from
`ANDY_PERMISSION_MODE`. See [`permission-spec.md`](permission-spec.md) §2.7–§2.9 for the full layering model.

## Verifying

The guarantee is covered by tests: `InjectionBootstrapTests` (engine level) and
`ContainerInjectionDiTests` (full DI + env) assert that injected allows run with **zero prompt calls**,
that fail-closed denies uncovered actions, and that `bypass` never overrides a `Deny`.
