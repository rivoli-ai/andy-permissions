namespace Andy.Permissions.Model;

/// <summary>
/// The outcome of evaluating a tool action against the permission rules.
/// </summary>
public enum PermissionOutcome
{
    /// <summary>The action is permitted without prompting.</summary>
    Allow = 0,

    /// <summary>The action requires interactive (or policy-driven) consent before proceeding.</summary>
    Ask = 1,

    /// <summary>The action is forbidden. Deny always wins over Allow/Ask (see RD2).</summary>
    Deny = 2,
}
