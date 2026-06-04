using Andy.Permissions.Model;

namespace Andy.Permissions.Store;

/// <summary>
/// Shipped defaults: a deliberately <em>minimal</em> set of truly-dangerous denies. Because Deny is
/// absolute (RD8) — not even an injected container rule can override it — this list is kept small and
/// specific so it rarely collides with legitimate needs. The <c>*</c> tool selector applies a path deny
/// across every file tool.
/// </summary>
public static class BuiltinRules
{
    private static readonly (string Text, PermissionOutcome Outcome)[] s_defaults =
    [
        // Secret/credential directories — never readable or writable by any tool.
        ("*(~/.ssh/**)", PermissionOutcome.Deny),
        ("*(~/.aws/**)", PermissionOutcome.Deny),
        ("*(~/.gnupg/**)", PermissionOutcome.Deny),
        ("*(~/.config/gcloud/**)", PermissionOutcome.Deny),
        ("*(~/.kube/**)", PermissionOutcome.Deny),

        // Catastrophic shell commands.
        ("bash_command(rm -rf /:*)", PermissionOutcome.Deny),
        ("execute_command(rm -rf /:*)", PermissionOutcome.Deny),
        ("bash_command(rm -rf /*:*)", PermissionOutcome.Deny),
        ("execute_command(rm -rf /*:*)", PermissionOutcome.Deny),
    ];

    /// <summary>The built-in rules, tagged <see cref="PermissionLayer.Builtin"/>.</summary>
    public static IReadOnlyList<PermissionRule> Default { get; } = BuildDefault();

    private static IReadOnlyList<PermissionRule> BuildDefault()
    {
        var rules = new List<PermissionRule>();
        foreach (var (text, outcome) in s_defaults)
        {
            if (PermissionRule.TryParse(text, outcome, PermissionLayer.Builtin, out var rule) && rule is not null)
            {
                rules.Add(rule);
            }
        }

        return rules;
    }
}
