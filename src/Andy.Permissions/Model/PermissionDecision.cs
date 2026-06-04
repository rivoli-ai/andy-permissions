namespace Andy.Permissions.Model;

/// <summary>
/// The result of asking a consent provider (<see cref="Andy.Permissions.Prompt.IPermissionPrompt"/>)
/// about an <see cref="PermissionOutcome.Ask"/> action. A decision is only ever Allow or Deny — never
/// Ask (RD5). Serializable so a future remote broker can return one over the wire.
/// </summary>
/// <param name="Allowed">True to permit the action, false to deny it.</param>
/// <param name="Persist">Whether/where to remember this decision for future calls.</param>
public sealed record PermissionDecision(bool Allowed, PersistScope Persist = PersistScope.Once)
{
    /// <summary>A one-off deny (used as the safe default by non-interactive providers).</summary>
    public static PermissionDecision DenyOnce { get; } = new(false, PersistScope.Once);

    /// <summary>A one-off allow.</summary>
    public static PermissionDecision AllowOnce { get; } = new(true, PersistScope.Once);
}
