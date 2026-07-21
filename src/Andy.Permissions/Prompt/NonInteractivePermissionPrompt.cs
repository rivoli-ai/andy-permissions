using Andy.Permissions.Model;

namespace Andy.Permissions.Prompt;

/// <summary>
/// The baseline preset a host runs under (spec §2.8). A mode is a <em>fallback shift</em>: it decides how
/// an <see cref="PermissionOutcome.Ask"/> is resolved when there is no interactive user to consult. No mode
/// can ever turn a <see cref="PermissionOutcome.Deny"/> into an Allow — Deny is resolved by the authorizer
/// before a prompt is reached, so a mode only ever reshapes Ask.
/// </summary>
public enum PermissionMode
{
    /// <summary>Deny anything that would prompt. The safe default for unattended/container runs (RD8/RD9).</summary>
    FailClosed = 0,

    /// <summary>
    /// The interactive baseline: writes/exec Ask for consent. With no TTY (this non-interactive provider)
    /// there is nobody to ask, so an Ask resolves to Deny — identical to <see cref="FailClosed"/> headless.
    /// </summary>
    Default = 1,

    /// <summary>
    /// Read-only/plan mode: nothing that requires consent may proceed. Reads the authorizer already allows
    /// still pass; every Ask resolves to Deny. Never relaxes anything, so it is always safe.
    /// </summary>
    Plan = 2,

    /// <summary>
    /// Auto-approve in-scope file edits: an Ask whose resources are all filesystem paths resolves to Allow;
    /// Asks that touch commands or network hosts still Deny (no TTY). Never affects Deny.
    /// </summary>
    AcceptEdits = 3,

    /// <summary>Trusted-sandbox ("yolo"): turn Ask into Allow. Never affects Deny (RD8). Explicit opt-in only.</summary>
    Bypass = 4,
}

/// <summary>
/// A consent provider for headless/container runs. It never overrides a Deny (those never reach a prompt —
/// the authorizer resolves Deny without asking). The configured <see cref="PermissionMode"/> decides how an
/// <see cref="PermissionOutcome.Ask"/> is resolved (see <see cref="ResolveAsk"/>). Decisions are not
/// persisted (<see cref="PersistScope.Once"/>).
/// </summary>
public sealed class NonInteractivePermissionPrompt : IPermissionPrompt
{
    private readonly PermissionMode _mode;

    public NonInteractivePermissionPrompt(PermissionMode mode) => _mode = mode;

    /// <summary>The mode this provider was configured with.</summary>
    public PermissionMode Mode => _mode;

    /// <inheritdoc />
    public Task<PermissionDecision> RequestAsync(PermissionRequest request, CancellationToken cancellationToken = default) =>
        Task.FromResult(ResolveAsk(_mode, request));

    /// <summary>
    /// Resolves an Ask into a concrete <see cref="PermissionDecision"/> for a given mode, with no user to
    /// consult. This is the single source of truth for headless mode behavior:
    /// <list type="bullet">
    /// <item><see cref="PermissionMode.Bypass"/> ⇒ Allow.</item>
    /// <item><see cref="PermissionMode.AcceptEdits"/> ⇒ Allow when every asked resource is a filesystem path; otherwise Deny.</item>
    /// <item><see cref="PermissionMode.FailClosed"/>, <see cref="PermissionMode.Default"/>, <see cref="PermissionMode.Plan"/> ⇒ Deny.</item>
    /// </list>
    /// Deny is never produced <em>from</em> a Deny here — Deny actions do not reach a prompt — so no mode can
    /// widen policy beyond Ask.
    /// </summary>
    public static PermissionDecision ResolveAsk(PermissionMode mode, PermissionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return mode switch
        {
            PermissionMode.Bypass => PermissionDecision.AllowOnce,
            PermissionMode.AcceptEdits => IsFileEditOnly(request) ? PermissionDecision.AllowOnce : PermissionDecision.DenyOnce,
            _ => PermissionDecision.DenyOnce,
        };
    }

    /// <summary>True when the Ask is driven purely by filesystem-path resources (an in-scope file edit).</summary>
    private static bool IsFileEditOnly(PermissionRequest request)
    {
        var asked = request.Evaluation.Resources.Where(r => r.Outcome == PermissionOutcome.Ask).ToList();
        return asked.Count > 0 && asked.All(r => r.Access.Kind == ResourceKind.Path);
    }

    /// <summary>
    /// Parses <c>ANDY_PERMISSION_MODE</c> into a <see cref="PermissionMode"/>. Recognizes
    /// <c>fail-closed</c>, <c>default</c>, <c>plan</c>, <c>accept-edits</c>, and <c>bypass</c>/<c>yolo</c>
    /// (case- and separator-insensitive: <c>-</c>/<c>_</c>/space are equivalent). Anything unrecognized —
    /// including null/empty/garbage — is <see cref="PermissionMode.FailClosed"/>, the safe default (RD9).
    /// </summary>
    public static PermissionMode ParseMode(string? value)
    {
        var normalized = value?.Trim().Replace('-', '_').Replace(' ', '_').ToLowerInvariant();
        return normalized switch
        {
            "bypass" or "yolo" => PermissionMode.Bypass,
            "accept_edits" or "acceptedits" => PermissionMode.AcceptEdits,
            "plan" => PermissionMode.Plan,
            "default" => PermissionMode.Default,
            _ => PermissionMode.FailClosed,
        };
    }
}
