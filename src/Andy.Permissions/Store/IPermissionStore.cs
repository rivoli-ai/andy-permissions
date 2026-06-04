using Andy.Permissions.Model;

namespace Andy.Permissions.Store;

/// <summary>
/// Provides the merged set of permission rules across all layers and persists remembered decisions.
/// Implementations cache the merged view in memory; <see cref="GetRules"/> is on the hot evaluation path.
/// </summary>
public interface IPermissionStore
{
    /// <summary>
    /// Returns the merged rules from every layer (builtin → user → project → local → session → injected).
    /// Layer precedence is applied by the authorizer, not here, so all matching rules are returned.
    /// </summary>
    IReadOnlyList<PermissionRule> GetRules();

    /// <summary>
    /// Persists a remembered decision to the given scope (file-backed for User/Project/Local, in-memory
    /// for Session) and refreshes the merged view. <see cref="PersistScope.Once"/> is a no-op.
    /// </summary>
    Task AppendRuleAsync(string toolId, string specifier, PermissionOutcome outcome, PersistScope scope, CancellationToken cancellationToken = default);

    /// <summary>Adds an in-memory rule for the current run (<see cref="PermissionLayer.Session"/>).</summary>
    void AddSessionRule(PermissionRule rule);

    /// <summary>
    /// Replaces the highest-precedence injected layer (container/CLI bootstrap, RD9). All supplied rules
    /// are tagged <see cref="PermissionLayer.Injected"/>.
    /// </summary>
    void SetInjectedRules(IEnumerable<PermissionRule> rules);
}
