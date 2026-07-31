# Andy.Permissions

A Claude-Code / opencode style tool permission and consent system for the Andy stack. It gates
`Andy.Tools` executions through an Allow / Ask / Deny rule engine with layered, file-backed
persistence, and supports injecting permissions up front so unattended container runs never prompt.

Repository: https://github.com/rivoli-ai/andy-permissions

> ALPHA RELEASE WARNING
>
> This software is in ALPHA stage. NO GUARANTEES are made about its functionality, stability, or safety.
>
> CRITICAL WARNINGS:
> - APIs, schemas, and storage formats may change without notice between releases.
> - Permission evaluation and enforcement are NOT FULLY TESTED for security-critical use.
> - DO NOT USE in production environments.
> - DO NOT rely on this as the sole control protecting sensitive files, credentials, or systems.
> - The authors assume NO RESPONSIBILITY for unauthorized access, data loss, or security breaches.
>
> USE AT YOUR OWN RISK.

## Overview

`Andy.Permissions` decides whether a tool call may proceed, by matching it against a merged set of
rules. Rules use the familiar `tool(specifier)` form (for example `read_file(~/.ssh/**)` or
`bash_command(git status:*)`) and resolve to one of three outcomes:

- `Allow` - proceed without prompting.
- `Ask` - request consent from the host (interactive prompt, container policy, or remote broker).
- `Deny` - block the call. Deny is absolute and is never overridden by an Allow in any layer.

Permissions apply to every tool, not just shell commands: you can ban reads of a directory, restrict
writes, scope network hosts, and require confirmation for destructive operations.

## Features

- Rule model with `tool(specifier)` parsing, mirroring Claude Code's `settings.json` permissions.
- Path matching with traversal-safe lexical normalization, command-prefix matching with argument
  boundaries, host/domain matching, and **symlink-aware deny** (a symlink in an allowed directory cannot
  reach a denied secret).
- A fail-closed shell command splitter so `git status && rm -rf /` cannot inherit an allow granted to
  `git status` — with **`bash -c` unwrapping**, **benign-wrapper stripping** (`timeout`, `nice`, `env`,
  …), **command-substitution surfacing**, **redirection detection**, and shell-function/fork-bomb
  rejection.
- A built-in **command classifier**: known read-only commands auto-allow on fallback, while dangerous
  commands (`rm -rf`, `sudo`, interpreters, `dd`, …) and output redirection raise a safety floor of Ask
  over broad allows. Argument-audited so `git -c`, `find -exec`, `sed -i`, `rg --pre` are not "safe".
- A precedence model where **Deny is absolute**, otherwise the highest-precedence layer wins, otherwise a
  tool-metadata fallback.
- Layered, corruption-resilient file store: **managed** (admin, uncoverable — discovered by default at
  `/etc/andy/permissions.managed.json`, or `%ProgramData%\andy\permissions.managed.json` on Windows), user,
  project, local, session, and injected layers with atomic writes.
- A pluggable consent seam (`IPermissionPrompt`) with a non-interactive provider for headless and
  container use (fail-closed or bypass), and **reject-with-feedback** surfaced back to the model.
- A decorating `IToolExecutor` that enforces decisions in front of any executor, plus dependency
  injection helpers and a container bootstrap driven by environment variables.

The full cross-tool best-of-breed specification and gap analysis is in
[`docs/permission-spec.md`](docs/permission-spec.md).

## Requirements

- .NET 10.0 SDK

## Build and test

```bash
dotnet restore
dotnet build
dotnet test
```

## Container usage

See [`docs/container-usage.md`](docs/container-usage.md) for the full guide (Docker examples, rules
format, modes) and [`examples/permissions.container.json`](examples/permissions.container.json) for a
ready-to-mount rules file.

For unattended runs, inject the rules up front so no consent is ever requested:

- `ANDY_PERMISSIONS_FILE` - path to a JSON rules file to load as the highest-precedence layer.
- `ANDY_PERMISSIONS_JSON` - inline JSON rules (used when no file is set).
- `ANDY_PERMISSION_MODE` - the baseline mode. A mode is a *fallback shift* over `Ask` (it never turns a
  `Deny` into an `Allow`). Headless resolution:
  - `fail-closed` (default, and any unrecognized value) - `Ask` ⇒ Deny; denies anything not pre-allowed.
  - `default` - the interactive baseline; with no TTY it denies like fail-closed.
  - `plan` - read-only; `Ask` ⇒ Deny (nothing needing consent proceeds).
  - `accept-edits` - `Ask` ⇒ Allow when every asked resource is a filesystem path (in-scope file edit),
    else Deny.
  - `bypass` (alias `yolo`) - `Ask` ⇒ Allow; still honors every Deny.

Rules file shape:

```json
{
  "allow": ["read_file(/workspace/**)", "bash_command(git:*)"],
  "ask":   ["write_file(/workspace/**)"],
  "deny":  ["read_file(~/.ssh/**)"]
}
```

## Project layout

```
src/Andy.Permissions/         The library (depends on Andy.Tools)
tests/Andy.Permissions.Tests/ xUnit test suite
```

## Design

The full design, review resolutions, and test matrix live in the `andy-engine` repository at
`docs/permissions-design.md`. Cross-repo work is tracked in the epic `rivoli-ai/andy-engine#5`.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for
details.
