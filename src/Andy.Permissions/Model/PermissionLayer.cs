namespace Andy.Permissions.Model;

/// <summary>
/// The source layer a permission rule comes from. Higher numeric value = higher precedence
/// among non-Deny outcomes (RD2 step 4). Deny is absolute across every layer (RD2 step 3),
/// so layer precedence only breaks ties between Allow/Ask matches.
/// </summary>
public enum PermissionLayer
{
    /// <summary>Shipped defaults (minimal, truly-dangerous denies + common safe allows).</summary>
    Builtin = 0,

    /// <summary>Per-user profile: <c>~/.andy/permissions.json</c>. "Allow always" default target.</summary>
    User = 1,

    /// <summary>Shared, committed project rules: <c>&lt;repo&gt;/.andy/permissions.json</c>.</summary>
    Project = 2,

    /// <summary>Personal, gitignored project rules: <c>&lt;repo&gt;/.andy/permissions.local.json</c>.</summary>
    Local = 3,

    /// <summary>In-memory "allow for this run only" decisions.</summary>
    Session = 4,

    /// <summary>Container/CLI bootstrap rules injected at startup (RD9).</summary>
    Injected = 5,

    /// <summary>
    /// Admin/enterprise-managed rules (e.g. a system <c>permissions.managed.json</c>). Highest precedence.
    /// Because Deny is absolute, a managed Deny can never be overridden by any lower layer (lockdown).
    /// </summary>
    Managed = 6,
}
