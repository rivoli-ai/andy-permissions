using Andy.Permissions.Model;

namespace Andy.Permissions.Authorization;

/// <summary>
/// Default <see cref="IToolActionResolver"/> with a built-in map for the known Andy.Tools library tools
/// (RD1). Unknown tools resolve to no resource (governed by tool-id rules + metadata fallback only).
/// The map is mutable so hosts can register custom tools' parameter roles.
/// </summary>
public sealed class DefaultToolActionResolver : IToolActionResolver
{
    private sealed record ParamRole(string ParameterName, ResourceKind Kind);

    // Single-file tools take the path under any of these parameter names. Listing the common aliases
    // (not just "file_path") keeps the resolved resource - and therefore the file name shown in the
    // permission prompt - present even when the call uses an alternate name, instead of degrading to
    // a "None" resource. Resolve() de-duplicates, so at most one Path resource results per call.
    private static readonly ParamRole[] FilePathRoles =
    [
        new("file_path", ResourceKind.Path),
        new("path", ResourceKind.Path),
        new("filepath", ResourceKind.Path),
        new("filename", ResourceKind.Path),
        new("file", ResourceKind.Path),
    ];

    private readonly Dictionary<string, ParamRole[]> _map = new(StringComparer.Ordinal)
    {
        ["read_file"] = FilePathRoles,
        ["write_file"] = FilePathRoles,
        ["delete_file"] = FilePathRoles,
        ["file_editor"] = FilePathRoles,
        ["list_directory"] = [new("path", ResourceKind.Path), new("directory_path", ResourceKind.Path)],
        ["search_text"] = [new("path", ResourceKind.Path), new("directory_path", ResourceKind.Path)],
        ["file_search"] = [new("path", ResourceKind.Path), new("directory_path", ResourceKind.Path)],
        ["replace_text"] = [new("path", ResourceKind.Path), new("file_path", ResourceKind.Path)],
        ["move_file"] = [new("source_path", ResourceKind.Path), new("destination_path", ResourceKind.Path)],
        ["copy_file"] = [new("source_path", ResourceKind.Path), new("destination_path", ResourceKind.Path)],
        ["bash_command"] = [new("command", ResourceKind.Command)],
        ["execute_command"] = [new("command", ResourceKind.Command)],
        ["http_request"] = [new("url", ResourceKind.Host)],
    };

    /// <summary>Registers (or overrides) the parameter roles for a tool id.</summary>
    public void Register(string toolId, params (string Parameter, ResourceKind Kind)[] roles)
    {
        _map[toolId] = roles.Select(r => new ParamRole(r.Parameter, r.Kind)).ToArray();
    }

    /// <inheritdoc />
    public IReadOnlyList<ResourceAccess> Resolve(string toolId, IReadOnlyDictionary<string, object?> parameters)
    {
        if (!_map.TryGetValue(toolId, out var roles))
        {
            return Array.Empty<ResourceAccess>();
        }

        var result = new List<ResourceAccess>();
        var seen = new HashSet<(ResourceKind, string)>();
        foreach (var role in roles)
        {
            var raw = GetString(parameters, role.ParameterName);
            if (string.IsNullOrEmpty(raw))
            {
                continue;
            }

            if (role.Kind == ResourceKind.Host)
            {
                var host = ExtractHost(raw);
                if (!string.IsNullOrEmpty(host) && seen.Add((ResourceKind.Host, host!)))
                {
                    result.Add(new ResourceAccess(ResourceKind.Host, host!));
                }
            }
            else if (seen.Add((role.Kind, raw)))
            {
                result.Add(new ResourceAccess(role.Kind, raw));
            }
        }

        return result;
    }

    private static string? GetString(IReadOnlyDictionary<string, object?> parameters, string key) =>
        parameters.TryGetValue(key, out var v) ? v?.ToString() : null;

    private static string? ExtractHost(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return uri.Host;
        }

        // Bare host or host:port without scheme.
        var trimmed = url.Trim();
        var slash = trimmed.IndexOf('/');
        if (slash >= 0)
        {
            trimmed = trimmed[..slash];
        }

        var colon = trimmed.IndexOf(':');
        if (colon >= 0)
        {
            trimmed = trimmed[..colon];
        }

        return trimmed.Length > 0 ? trimmed : null;
    }
}
