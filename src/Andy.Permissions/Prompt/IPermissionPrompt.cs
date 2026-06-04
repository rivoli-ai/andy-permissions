using Andy.Permissions.Model;

namespace Andy.Permissions.Prompt;

/// <summary>
/// The consent seam. When an action evaluates to <see cref="PermissionOutcome.Ask"/>, the decorator calls
/// this to obtain a decision. Hosts supply the implementation: an interactive TUI (andy-cli), a
/// non-interactive policy (containers, see <see cref="NonInteractivePermissionPrompt"/>), a scripted test
/// double, or a future remote broker. Implementations must be safe to call from a serialized context
/// (the decorator serializes prompts, RD4).
/// </summary>
public interface IPermissionPrompt
{
    /// <summary>Requests a decision for an Ask action. Cancellation should resolve to a deny.</summary>
    Task<PermissionDecision> RequestAsync(PermissionRequest request, CancellationToken cancellationToken = default);
}
