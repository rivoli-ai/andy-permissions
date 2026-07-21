# Tool Permissions — Consolidated Best-of-Breed Specification

**Status:** Authoritative spec for `andy-permissions` · **Date:** 2026-06-04

This spec consolidates a code-level study of how leading coding agents gate tool use, into a single
model that `andy-permissions` implements. It also records the gap analysis against our implementation
and what is intentionally deferred.

## Sources studied (code unless noted)

| Tool | What we learned (one line) |
|---|---|
| **Gemini CLI** (`google-gemini/gemini-cli`) | Central priority-ordered policy engine; deep shell parsing (recursive split, `bash -c` unwrap, redirection downgrade, per-flag `git`/`find`/`rg` auditing); seatbelt/docker/gVisor sandbox; trusted-folders. |
| **Codex CLI** (`openai/codex`) | Two axes: **approval policy × OS sandbox** (Seatbelt / bubblewrap+seccomp / restricted-token); network off by default; Starlark `prefix_rule`/`network_rule`; protected `.git`; session vs persisted approvals. |
| **opencode** (`sst/opencode`) | Uniform `(action, resource, effect)` rules, last-match-wins; config `deny` absolute over runtime "always"; per-agent rulesets; `external_directory` path-scoping. **No sandbox.** |
| **Qwen Code** (`QwenLM/qwen-code`) | gemini fork; richest rule grammar (`Bash(git *)`, `Read(./x/**)`, `WebFetch(domain:)`); **virtual shell-op extraction** (a `cat`/`curl` inside Bash also matches Read/WebFetch rules); AST read-only detection; LLM `auto` classifier; dangerous-rule stripping. |
| **Kimi CLI** (`MoonshotAI/kimi-cli`) | Coarse per-action approval; YOLO/AFK/Plan modes; PreToolUse hooks as deny gate; reject-with-feedback. **No sandbox, no command scoping.** |
| **Aider** (`Aider-AI/aider`) | Minimal: confirm + `--yes`; **git auto-commit as the safety net**; explicit-yes for shell. |
| **Crush** (`charmbracelet/crush`) | `{tool, action, path}` keyed; `allowed_tools` whole-tool/`tool:action`; PreToolUse hooks; "always" session-only. |
| **Claude Code** (docs only) | Tiered read/edit/bash; `allow`/`ask`/`deny` rule arrays; `Tool(specifier)` grammar; modes (default/acceptEdits/plan/auto/dontAsk/bypass); managed→cmdline→local→project→user scopes; protected paths; OS sandbox; PreToolUse hooks. |

## 1. Universal patterns (every serious tool does these)

1. **Three outcomes: Allow / Ask / Deny.**
2. **Deny is absolute** — a deny at any layer beats any allow (Gemini priority, opencode short-circuit, Claude "deny wins", Codex Forbidden).
3. **Layered config with precedence** — at minimum user + project; mature tools add managed/enterprise (uncoverable), session, and injected/runtime.
4. **Bash is special** — the command string must be *parsed*, not string-matched: split on `&& || ; |` and evaluate each sub-command; the aggregate is the **most restrictive**.
5. **Read-only is cheap** — reads and a known-safe command set run without prompting; writes/exec/network prompt by default.
6. **"Always" persistence** — approving once can be remembered (session and/or to a file), stored as a *narrow* rule (command prefix or path), not the raw string.
7. **A non-interactive escape** — a YOLO/bypass mode for sandboxed/CI use, and a fail-closed mode for headless.

## 2. The consolidated model (what andy-permissions implements)

### 2.1 Rule = `tool(specifier) → outcome @ layer`
- `tool` = snake_case tool id, or `*`.
- `specifier` per resource kind: **Path** glob, **Command** prefix (`cmd:*`) / glob, **Host** (`domain:h` / `*.h`), or `*`.
- `outcome` ∈ {Allow, Ask, Deny}.
- Text form mirrors Claude Code: `read_file(~/.ssh/**)`, `execute_command(git status:*)`, `http_request(domain:example.com)`.

### 2.2 Resources per tool (resolver)
A tool call resolves to ≥0 governed resources (Qwen/opencode style). Multi-path tools (`move_file`,
`copy_file`) yield two Path resources; a **deny on either blocks** (most-restrictive combine).

### 2.3 Precedence (security-first; resolves the cross-tool disagreement)
1. Resolve resources; Command resources are **decomposed** (§2.4).
2. **Deny is absolute** across every layer (Gemini/Claude/opencode/Codex consensus). A hostile project
   file or an injected container rule can **never** un-deny a builtin/managed deny.
3. Else the **highest-precedence layer** that matched wins: `Managed > Injected > Session > Local > Project > User > Builtin`. Within a layer, **most-specific** specifier wins.
4. Else **fallback** from command classification (§2.5) and tool metadata
   (`RequiresConfirmation` / dangerous capabilities ⇒ Ask; otherwise Allow).
5. Combine per-resource outcomes as **Deny > Ask > Allow**.

> Note: we choose **deny-absolute** over Claude's first-match and Gemini's numeric priority because it
> is the simplest model that is provably safe against hostile lower-precedence config (the C4 attack).

### 2.4 Shell handling (the crown jewel — where most tools are weakest)
A Command resource is parsed into independently-authorized sub-commands. Required behaviors, drawn from
the union of Gemini + Codex + Qwen (the three strongest):
- **Split** on `&& || ; | & \n`, brace/subshell groups; quotes and escapes respected.
- **Substitution surfaced** — `$(...)`, backticks, `<(...)`/`>(...)` inner commands become their own
  segments (so `echo $(rm -rf /)` is caught).
- **Wrapper unwrapping** — `bash -c "..."` / `sh -c`, and prefix wrappers `env VAR=v`, `sudo`,
  `timeout N`, `nice`, `nohup`, `stdbuf`, `xargs` are peeled so the *real* command is evaluated
  (closes the `bash -c "rm -rf /"` bypass).
- **Leading env assignments stripped** (`FOO=bar cmd` ⇒ `cmd`), but their values are still scanned for
  substitution (`FOO=$(curl evil)` is surfaced).
- **Redirection downgrade** — a segment containing `>`/`>>`/`>&`/`>(`/`/dev/tcp` cannot be silently
  Allowed (exfiltration risk); Allow ⇒ Ask.
- **Fail closed** — any segment that cannot be tokenized confidently (unbalanced quotes, NUL,
  unterminated heredoc, excessive nesting) can never be Allowed (⇒ Ask, or Deny in strict mode).
- **Aggregate = most restrictive** across all segments.

### 2.5 Command classification (good defaults without nagging)
A built-in classifier, used only for the no-explicit-rule fallback and as a safety floor:
- **Known-safe read-only** (`ls cat grep head tail wc which pwd echo stat find(read-only) git(status/log/diff/show/branch) …`) ⇒ fallback **Allow** (matches Gemini/Codex/Claude read-only sets). Arg-audited: `git -c`, `find -exec/-delete`, `rg --pre`, `base64 -o` are *not* safe.
- **Dangerous** (`rm -rf`, `sudo`, `mkfs`, `dd`, `:(){`, `curl|sh`, `chmod -R 777`, writes to `/dev/…`) ⇒ safety **floor of Ask** even if a *broad* allow matched (Gemini `isDangerousCommand`). An explicit `Deny` still wins; an explicit narrow `Allow` for that exact command is honored; `bypass` mode collapses the Ask.
- Everything else ⇒ Ask (because the tool has the ProcessExecution capability).

### 2.6 Path specifiers
- `//abs` = filesystem-absolute (Claude convention); `/abs` also treated as absolute (POSIX-natural);
  `~/p` = home; `./p` or bare = relative to the call's working directory.
- Matching normalizes both sides **lexically** (no `Path.GetFullPath` — deterministic cross-platform),
  collapsing `.`/`..`/`//`, so `/etc/./passwd` cannot dodge `/etc/**`. `OrdinalIgnoreCase` to mirror
  case-insensitive filesystems.
- `**` crosses directories, `*` does not; trailing `/**` also matches the directory itself.
- **Symlink-aware deny** (Claude): a Deny matches if **either** the literal path **or** its resolved
  real path matches — closes the "symlink in an allowed dir → secret" exfiltration. (Allow still
  matches on the literal path; the tool re-checks at I/O time — TOCTOU residual, documented.)

### 2.7 Layers & persistence
Files mirror Claude Code's hierarchy:
- **Managed** (admin, uncoverable): discovered **by default** at `/etc/andy/permissions.managed.json`
  (or `%ProgramData%\andy\permissions.managed.json` on Windows). The file is optional; a host can relocate
  it via `PermissionStoreOptions.ManagedFilePath` or set it to `null` to disable managed discovery.
- **User**: `~/.andy/permissions.json`.
- **Project**: `<repo>/.andy/permissions.json` (committed).
- **Local**: `<repo>/.andy/permissions.local.json` (gitignored).
- **Session**: in-memory.
- **Injected**: container bootstrap (`ANDY_PERMISSIONS_FILE` / `_JSON`), highest non-managed.
- File format = `{ "allow": [...], "ask": [...], "deny": [...] }` (Claude-compatible), corruption-resilient.
- "Always allow/deny" persists a **narrow** rule (path = the concrete path; command = `segment:*`) to the
  chosen scope; config `deny` is never overridden by a persisted "always".

### 2.8 Modes (baseline presets) and the consent seam
- **Modes** (Claude/Gemini/Qwen/Kimi consensus) are a **fallback shift**: they decide how an `Ask` is
  resolved when there is no interactive user to consult, and **can never turn a `Deny` into an `Allow`**
  (Deny is resolved by the authorizer before a prompt is reached). The `PermissionMode` enum and
  `NonInteractivePermissionPrompt.ResolveAsk` are the public API; headless resolution of an `Ask`:
  - `failClosed` ⇒ Deny (the default; also any unrecognized `ANDY_PERMISSION_MODE`).
  - `default` ⇒ Deny with no TTY (the interactive baseline: ask writes/exec when a user is present).
  - `plan` ⇒ Deny (read-only; nothing needing consent proceeds).
  - `acceptEdits` ⇒ Allow when every asked resource is a filesystem path (in-scope file edit), else Deny.
  - `yolo`/`bypass` ⇒ Allow (trusted sandbox), still honoring every Deny.

  Interactive hosts supply their own `IPermissionPrompt` and apply the same shift (e.g. `default` asks,
  `plan` denies writes, `acceptEdits` auto-approves file edits). Env parsing accepts `-`/`_`/space
  interchangeably and is case-insensitive.
- **Consent seam** `IPermissionPrompt` (host-supplied): interactive TUI, non-interactive policy
  (container), or a future remote broker. Decisions: Allow/Deny + persist scope + **optional feedback**
  to the model (Kimi/opencode reject-with-feedback). Prompts are **serialized** and **re-checked** under
  a lock so parallel tool calls don't double-prompt or race the store.

### 2.9 Complementary layer: OS sandbox (delegated)
The strongest tools (Codex, Gemini) add OS-level isolation (Seatbelt / bubblewrap+seccomp / restricted
token; network off by default). In the Andy model the **container is the sandbox** (Phase 4): the rule
engine is the *consent* layer; the container bounds the *blast radius*. OS-level sandboxing of host runs
is a documented future layer, not a v1 engine feature.

### 2.10 Programmable policy hook (future)
Every mature tool exposes a PreToolUse hook that can allow/deny/ask before the engine. Mapped to a
future `IPolicyHook` running ahead of the authorizer.

## 3. Gap analysis vs the andy-permissions implementation

| Capability | Pre-hardening | Action |
|---|---|---|
| Three outcomes, deny-absolute, layered precedence | ✅ | keep |
| Lexical traversal-safe path normalization | ✅ | keep |
| Bash split + substitution + fail-closed + most-restrictive | ✅ | keep |
| Multi-resource (move/copy) | ✅ | keep |
| **Shell wrapper / `bash -c` unwrap** | ❌ | **ADD** |
| **Process-wrapper prefix strip (`sudo`/`timeout`/`env`/…)** | ❌ | **ADD** |
| **Redirection downgrade** | ❌ | **ADD** |
| **Known-safe read-only auto-allow + dangerous floor** | partial (only `rm -rf /` deny) | **ADD classifier** |
| **Symlink-aware deny** | ❌ (documented TOCTOU) | **ADD** |
| **`//` absolute path prefix** | partial (`/`=abs) | **ADD `//`** |
| **Reject-with-feedback** | ❌ | **ADD field** |
| **Managed (uncoverable) layer** | ❌ | ✅ added — **discovered by default** at the platform managed path (§2.7) |
| Mode presets (plan/default/acceptEdits/yolo/failClosed) | partial (failClosed/bypass prompts) | ✅ added — full mode set as a fallback shift, never overriding Deny (§2.8) |
| Virtual shell-op extraction (cat/curl inside bash → Read/WebFetch rules) | ❌ | document (future) |
| OS sandbox (seatbelt/bwrap) | n/a (container model) | document (Phase 4) |
| PreToolUse policy hook | ❌ | document (future) |

## 4. What is intentionally deferred (with rationale)
- **OS-level sandboxing** — the container is the blast-radius boundary in the Andy model; host-run
  seatbelt/bwrap is a large, platform-specific effort for a later phase.
- **LLM `auto` classifier** (Claude/Qwen) — depends on a model call per action; a product decision.
- **Virtual shell-op extraction** — high value but needs a per-command arg→resource mapper; tracked.
- **Full `git -c` / `find -exec` per-flag auditing** — partially covered by the dangerous set; deep
  per-flag allowlists (Gemini/Codex) are a follow-up.

## 5. Test obligations (every behavior above has tests)
See `tests/Andy.Permissions.Tests`. Security-critical suites: `BashCommandSplitterTests` (wrappers,
substitution, redirection, fail-closed), `CommandClassifierTests` (safe/dangerous + arg audit),
`ToolPermissionAuthorizerTests` (precedence truth table, classifier integration, redirection downgrade),
`SpecifierMatcherTests` (traversal, `//`, symlink-deny), `PermissionedToolExecutorTests` (allow/deny/ask,
serialization, persistence, feedback), `FilePermissionStoreTests` (layers incl. managed, atomicity),
`InjectionBootstrapTests` (container zero-prompt guarantee), and a dedicated **`SecurityBypassTests`**
asserting known injection/escape vectors never resolve to Allow.
