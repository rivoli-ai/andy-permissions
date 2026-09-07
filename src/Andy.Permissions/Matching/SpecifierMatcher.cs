using System.Text;
using System.Text.RegularExpressions;
using Andy.Permissions.Model;
using Andy.Tools.Library.Common;

namespace Andy.Permissions.Matching;

/// <summary>
/// Matches rule specifiers against concrete resources. Path matching normalizes both sides identically
/// (so traversal tricks like <c>/etc/./passwd</c> can't dodge a <c>/etc/**</c> deny — C2) and uses
/// <see cref="StringComparison.OrdinalIgnoreCase"/> to mirror <c>SecurityManager</c> on case-insensitive
/// filesystems. Command matching supports the <c>prefix:*</c> convention with argument boundaries.
/// </summary>
public static class SpecifierMatcher
{
    /// <summary>True if a rule's tool selector matches the given tool id.</summary>
    public static bool MatchesTool(string ruleTool, string toolId) =>
        ruleTool == "*" || string.Equals(ruleTool, toolId, StringComparison.Ordinal);

    /// <summary>True if a rule specifier matches a concrete <see cref="ResourceAccess"/>.</summary>
    public static bool MatchesResource(string specifier, ResourceAccess access, string? workingDirectory) =>
        access.Kind switch
        {
            ResourceKind.Path => MatchPath(specifier, access.Value, workingDirectory),
            ResourceKind.Command => MatchCommand(specifier, access.Value),
            ResourceKind.Host => MatchHost(specifier, access.Value),
            ResourceKind.None => specifier == "*",
            _ => false,
        };

    // ---- Paths -------------------------------------------------------------------------------

    /// <summary>Matches a path glob specifier against a concrete path, normalizing both sides.</summary>
    public static bool MatchPath(string specifier, string value, string? workingDirectory)
    {
        if (specifier == "*" || specifier == "**")
        {
            return true;
        }

        var normSpec = NormalizeSpecifierPath(specifier, workingDirectory);
        var normValue = NormalizeConcretePath(value, workingDirectory);
        if (normValue is null)
        {
            return false;
        }

        var regex = GlobToRegex(normSpec, matchAcrossSeparators: false);
        return regex.IsMatch(normValue);
    }

    /// <summary>
    /// Normalizes a concrete path <em>lexically</em> (deterministic across OSes, no filesystem access):
    /// expand <c>~</c>, unify separators to '/', resolve relative against the working dir, and collapse
    /// <c>.</c>/<c>..</c>/duplicate separators. We deliberately avoid <see cref="Path.GetFullPath(string)"/>
    /// because it is platform-dependent (a POSIX-style <c>/etc</c> becomes <c>C:\etc</c> on Windows), which
    /// would make rule matching differ by OS. Returns null on an unusable path. Note: symlinks are not
    /// resolved (matching is on the textual path; the tool re-checks at I/O time — see C1/TOCTOU).
    /// </summary>
    public static string? NormalizeConcretePath(string value, string? workingDirectory)
    {
        if (string.IsNullOrWhiteSpace(value) || value.IndexOf('\0') >= 0)
        {
            return null;
        }

        return NormalizeSpecifierPath(value, workingDirectory);
    }

    /// <summary>
    /// Lexically normalizes a specifier path while preserving glob wildcards: expand <c>~</c>, prefix the
    /// working dir if relative, unify separators, and collapse redundant <c>.</c>/<c>//</c> segments
    /// (without star-mangling that <see cref="Path.GetFullPath(string)"/> would cause).
    /// </summary>
    public static string NormalizeSpecifierPath(string specifier, string? workingDirectory)
    {
        var expanded = ExpandHome(specifier);
        expanded = UnifySeparators(expanded);

        var rooted = expanded.StartsWith('/') || HasWindowsRoot(expanded);
        if (!rooted)
        {
            var baseDir = UnifySeparators(string.IsNullOrEmpty(workingDirectory)
                ? Directory.GetCurrentDirectory()
                : ExpandHome(workingDirectory!));
            expanded = baseDir.TrimEnd('/') + "/" + expanded;
        }

        return CollapseDotSegments(expanded);
    }

    /// <summary>
    /// Resolves a path's real (symlink-followed) location, normalized, or null if it
    /// can't be resolved. Existing parent links are resolved even for new files.
    /// Used for symlink-aware Deny matching (so a symlink inside an allowed directory
    /// that points at a denied secret is still blocked).
    /// </summary>
    public static string? ResolveRealPath(string value, string? workingDirectory)
    {
        var norm = NormalizeConcretePath(value, workingDirectory);
        if (norm is null)
        {
            return null;
        }

        try
        {
            // Share the execution layer's component-by-component resolver.
            // ResolveLinkTarget on the leaf alone misses directory symlinks.
            return UnifySeparators(ToolHelpers.ResolveRealPath(norm));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static string ExpandHome(string path)
    {
        if (path == "~")
        {
            return Home;
        }

        if (path.StartsWith("~/", StringComparison.Ordinal) || path.StartsWith("~\\", StringComparison.Ordinal))
        {
            return Home + path[1..];
        }

        // "~user/..." is intentionally NOT expanded (a naive replace corrupts it); left literal.
        return path;
    }

    private static string Home => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static string UnifySeparators(string path) => path.Replace('\\', '/');

    private static bool HasWindowsRoot(string path) =>
        path.Length >= 2 && char.IsLetter(path[0]) && path[1] == ':';

    private static string CollapseDotSegments(string path)
    {
        var rooted = path.StartsWith('/');
        var winRoot = HasWindowsRoot(path);
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var stack = new List<string>();
        foreach (var part in parts)
        {
            if (part == ".")
            {
                continue;
            }

            if (part == ".." && stack.Count > 0 && stack[^1] != "..")
            {
                stack.RemoveAt(stack.Count - 1);
                continue;
            }

            stack.Add(part);
        }

        var body = string.Join('/', stack);
        if (winRoot)
        {
            return body;
        }

        return rooted ? "/" + body : body;
    }

    // ---- Commands ----------------------------------------------------------------------------

    /// <summary>
    /// Matches a command specifier against a command string. <c>*</c> matches anything; <c>prefix:*</c>
    /// matches a command equal to <c>prefix</c> or starting with <c>prefix</c> + whitespace (argument
    /// boundary, so <c>git status</c> never matches <c>git statusx</c>); otherwise glob match.
    /// </summary>
    public static bool MatchCommand(string specifier, string command)
    {
        var cmd = command.Trim();
        if (specifier == "*")
        {
            return true;
        }

        if (specifier.EndsWith(":*", StringComparison.Ordinal))
        {
            var prefix = specifier[..^2].Trim();
            if (cmd.Equals(prefix, StringComparison.Ordinal))
            {
                return true;
            }

            return cmd.Length > prefix.Length
                && cmd.StartsWith(prefix, StringComparison.Ordinal)
                && char.IsWhiteSpace(cmd[prefix.Length]);
        }

        return GlobToRegex(specifier, matchAcrossSeparators: true).IsMatch(cmd);
    }

    // ---- Hosts -------------------------------------------------------------------------------

    /// <summary>Matches a host specifier (<c>domain:host</c>, <c>host</c>, or <c>*.host</c>) against a host.</summary>
    public static bool MatchHost(string specifier, string host)
    {
        var spec = specifier.StartsWith("domain:", StringComparison.OrdinalIgnoreCase)
            ? specifier["domain:".Length..]
            : specifier;

        if (spec == "*")
        {
            return true;
        }

        if (spec.StartsWith("*.", StringComparison.Ordinal))
        {
            return host.EndsWith(spec[1..], StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(host, spec, StringComparison.OrdinalIgnoreCase);
    }

    // ---- Glob engine -------------------------------------------------------------------------

    private static readonly Dictionary<string, Regex> s_regexCache = new(StringComparer.Ordinal);
    private static readonly object s_cacheLock = new();

    private static Regex GlobToRegex(string glob, bool matchAcrossSeparators)
    {
        var key = (matchAcrossSeparators ? "X:" : "S:") + glob;
        lock (s_cacheLock)
        {
            if (s_regexCache.TryGetValue(key, out var cached))
            {
                return cached;
            }

            var regex = new Regex(BuildPattern(glob, matchAcrossSeparators),
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            s_regexCache[key] = regex;
            return regex;
        }
    }

    private static string BuildPattern(string glob, bool matchAcrossSeparators)
    {
        var sb = new StringBuilder("^");
        for (var i = 0; i < glob.Length; i++)
        {
            var c = glob[i];
            switch (c)
            {
                case '*':
                    if (i + 1 < glob.Length && glob[i + 1] == '*')
                    {
                        i++;
                        // Trailing "/**" also matches the directory itself: "/etc/**" ⇒ "/etc" and below.
                        if (sb.Length >= 2 && sb[^1] == '/' && i + 1 >= glob.Length)
                        {
                            sb.Length -= 1; // drop the '/'
                            sb.Append("(/.*)?");
                        }
                        else
                        {
                            sb.Append(".*");
                        }
                    }
                    else
                    {
                        sb.Append(matchAcrossSeparators ? ".*" : "[^/]*");
                    }

                    break;
                case '?':
                    sb.Append(matchAcrossSeparators ? '.' : "[^/]");
                    break;
                default:
                    sb.Append(Regex.Escape(c.ToString()));
                    break;
            }
        }

        sb.Append('$');
        return sb.ToString();
    }
}
