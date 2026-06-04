namespace Andy.Permissions.Model;

/// <summary>
/// Where a remembered "allow always" / "deny always" decision should be persisted.
/// </summary>
public enum PersistScope
{
    /// <summary>Do not remember; applies to this single call only.</summary>
    Once = 0,

    /// <summary>Remember for the rest of this process run (in-memory <see cref="PermissionLayer.Session"/>).</summary>
    Session = 1,

    /// <summary>Persist to the shared, committed project file (<see cref="PermissionLayer.Project"/>).</summary>
    Project = 2,

    /// <summary>Persist to the gitignored local project file (<see cref="PermissionLayer.Local"/>).</summary>
    Local = 3,

    /// <summary>Persist to the per-user profile (<see cref="PermissionLayer.User"/>).</summary>
    User = 4,
}
