using Andy.Permissions.Model;

namespace Andy.Permissions.Store;

/// <summary>
/// Configures where <see cref="FilePermissionStore"/> reads/writes each persisted layer. Any null path
/// disables that layer (treated as empty). The builtin layer defaults to <see cref="BuiltinRules.Default"/>.
/// </summary>
public sealed class PermissionStoreOptions
{
    /// <summary>
    /// Admin/enterprise-managed file (highest precedence; a managed Deny is uncoverable). Null by default
    /// (opt-in); a host can point this at a system path such as <c>/etc/andy/permissions.managed.json</c>.
    /// </summary>
    public string? ManagedFilePath { get; set; }

    /// <summary>Per-user file, default <c>~/.andy/permissions.json</c>.</summary>
    public string? UserFilePath { get; set; } = DefaultUserFilePath();

    /// <summary>Shared, committed project file, e.g. <c>&lt;repo&gt;/.andy/permissions.json</c>.</summary>
    public string? ProjectFilePath { get; set; }

    /// <summary>Gitignored local project file, e.g. <c>&lt;repo&gt;/.andy/permissions.local.json</c>.</summary>
    public string? LocalFilePath { get; set; }

    /// <summary>The builtin rules (lowest precedence). Defaults to <see cref="BuiltinRules.Default"/>.</summary>
    public IReadOnlyList<PermissionRule> Builtin { get; set; } = BuiltinRules.Default;

    /// <summary>Computes the default <c>~/.andy/permissions.json</c> path.</summary>
    public static string DefaultUserFilePath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".andy", "permissions.json");

    /// <summary>Convenience: sets project + local file paths from a repo's <c>.andy</c> directory.</summary>
    public PermissionStoreOptions WithProjectDirectory(string repoRoot)
    {
        ProjectFilePath = Path.Combine(repoRoot, ".andy", "permissions.json");
        LocalFilePath = Path.Combine(repoRoot, ".andy", "permissions.local.json");
        return this;
    }
}
