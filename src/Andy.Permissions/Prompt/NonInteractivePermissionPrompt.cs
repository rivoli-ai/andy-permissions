using Andy.Permissions.Model;

namespace Andy.Permissions.Prompt;

/// <summary>
/// How a non-interactive host resolves <see cref="PermissionOutcome.Ask"/> actions when there is no TTY.
/// </summary>
public enum PermissionMode
{
    /// <summary>Deny anything that would prompt. The safe default for unattended/container runs (RD8/RD9).</summary>
    FailClosed = 0,

    /// <summary>Trusted-sandbox: turn Ask into Allow. Never affects Deny (RD8). Explicit opt-in only.</summary>
    Bypass = 1,
}

/// <summary>
/// A consent provider for headless/container runs. It never overrides a Deny (those never reach a prompt —
/// the authorizer resolves Deny without asking). In <see cref="PermissionMode.FailClosed"/> it denies; in
/// <see cref="PermissionMode.Bypass"/> it allows. Decisions are not persisted (<see cref="PersistScope.Once"/>).
/// </summary>
public sealed class NonInteractivePermissionPrompt : IPermissionPrompt
{
    private readonly PermissionMode _mode;

    public NonInteractivePermissionPrompt(PermissionMode mode) => _mode = mode;

    /// <summary>The mode this provider was configured with.</summary>
    public PermissionMode Mode => _mode;

    /// <inheritdoc />
    public Task<PermissionDecision> RequestAsync(PermissionRequest request, CancellationToken cancellationToken = default) =>
        Task.FromResult(_mode == PermissionMode.Bypass ? PermissionDecision.AllowOnce : PermissionDecision.DenyOnce);

    /// <summary>
    /// Parses <c>ANDY_PERMISSION_MODE</c>; anything unrecognized (including null/empty/garbage) is
    /// <see cref="PermissionMode.FailClosed"/> (RD9).
    /// </summary>
    public static PermissionMode ParseMode(string? value) =>
        string.Equals(value?.Trim(), "bypass", StringComparison.OrdinalIgnoreCase)
            ? PermissionMode.Bypass
            : PermissionMode.FailClosed;
}
