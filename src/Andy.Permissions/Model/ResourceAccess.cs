namespace Andy.Permissions.Model;

/// <summary>
/// The kind of resource a tool parameter represents, used to choose the matching strategy.
/// </summary>
public enum ResourceKind
{
    /// <summary>No governable resource (rule matched purely by tool id / metadata fallback).</summary>
    None = 0,

    /// <summary>A filesystem path (glob + path-normalized matching).</summary>
    Path = 1,

    /// <summary>A shell command string (split into segments; command-prefix matching).</summary>
    Command = 2,

    /// <summary>A network host (host / wildcard-domain matching).</summary>
    Host = 3,
}

/// <summary>
/// A single concrete resource that a tool call wants to act on, derived from its parameters by an
/// <see cref="Andy.Permissions.Authorization.IToolActionResolver"/>. One tool call can yield several
/// (e.g. <c>move_file</c> has a source and a destination path).
/// </summary>
/// <param name="Kind">The resource kind.</param>
/// <param name="Value">The resource value (path / command / host).</param>
public readonly record struct ResourceAccess(ResourceKind Kind, string Value);
