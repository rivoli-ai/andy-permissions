using Andy.Permissions.Model;

namespace Andy.Permissions.Authorization;

/// <summary>
/// Maps a tool call's parameters to the concrete resources it would touch, so the authorizer knows which
/// specifiers to match. One tool can yield several resources (e.g. <c>move_file</c> → source + destination).
/// </summary>
public interface IToolActionResolver
{
    /// <summary>
    /// Resolves the resources governed by a tool call. Returns an empty list when the tool governs no
    /// matchable resource (the authorizer then relies on the tool-id rule and metadata fallback).
    /// </summary>
    IReadOnlyList<ResourceAccess> Resolve(string toolId, IReadOnlyDictionary<string, object?> parameters);
}
