using System.Text.RegularExpressions;

namespace Andy.Permissions.Matching;

/// <summary>How a single command segment is classified for fallback/safety purposes.</summary>
public enum CommandClass
{
    /// <summary>No strong signal — handled by rules and the metadata fallback (typically Ask).</summary>
    Neutral = 0,

    /// <summary>A known read-only command (and its args pass audit). Safe to auto-Allow on fallback.</summary>
    KnownSafeReadOnly = 1,

    /// <summary>A destructive/code-executing command. Raises a safety floor of Ask over broad allows.</summary>
    Dangerous = 2,
}

/// <summary>
/// Classifies a single (already wrapper-unwrapped) command segment as known-safe-read-only, dangerous, or
/// neutral. Mirrors the safe/dangerous heuristics in Gemini CLI and Codex CLI, including argument auditing
/// so that "safe" tools used in unsafe ways (<c>git -c</c>, <c>find -exec</c>, <c>sed -i</c>, <c>rg --pre</c>)
/// are NOT treated as safe. Used only for the no-explicit-rule fallback and as a safety floor — explicit
/// rules always take precedence.
/// </summary>
public static class CommandClassifier
{
    private static readonly HashSet<string> s_safeRoots = new(StringComparer.Ordinal)
    {
        "ls", "cat", "echo", "pwd", "head", "tail", "wc", "which", "whoami", "id", "hostname", "uname",
        "date", "printenv", "stat", "du", "df", "file", "basename", "dirname", "realpath", "readlink",
        "tree", "nl", "rev", "tac", "seq", "cut", "tr", "sort", "uniq", "comm", "diff", "cmp", "grep",
        "egrep", "fgrep", "column", "fold", "true", "false", "test", "printf",
    };

    private static readonly HashSet<string> s_dangerousRoots = new(StringComparer.Ordinal)
    {
        "sudo", "su", "doas", "dd", "fdisk", "parted", "sfdisk", "mkswap", "wipefs", "shred",
        "shutdown", "reboot", "halt", "poweroff", "init", "telinit", "eval", "exec", "source",
        "chpasswd", "passwd", "useradd", "userdel", "usermod", "visudo", "groupadd",
        "mount", "umount", "chroot", "iptables", "ip6tables", "ufw", "nft", "sysctl",
        "crontab", "at", "systemctl", "service", "launchctl",
        "nc", "ncat", "netcat", "socat", "telnet",
        // Interpreters that can execute arbitrary code from flags/stdin:
        "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "osascript",
        "pwsh", "powershell", "deno", "bun",
        // Bare shells (e.g. a pipe target `curl ... | sh`):
        "sh", "bash", "zsh", "dash", "ksh", "fish",
    };

    /// <summary>Classifies a command segment.</summary>
    public static CommandClass Classify(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return CommandClass.Neutral;
        }

        // Fork bomb, e.g. :(){ :|:& };:
        if (command.Replace(" ", string.Empty).Contains(":(){", StringComparison.Ordinal))
        {
            return CommandClass.Dangerous;
        }

        var tokens = command.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
        {
            return CommandClass.Neutral;
        }

        var root = LeafName(tokens[0]);

        if (s_dangerousRoots.Contains(root))
        {
            return CommandClass.Dangerous;
        }

        if (root == "rm" && tokens.Skip(1).Any(t => t.StartsWith('-') && (t.Contains('r') || t.Contains('f'))))
        {
            return CommandClass.Dangerous;
        }

        if ((root == "chmod" || root == "chown")
            && tokens.Skip(1).Any(t => t.Contains('R') || t == "777" || t == "-R"))
        {
            return CommandClass.Dangerous;
        }

        return ClassifySafe(root, tokens) ? CommandClass.KnownSafeReadOnly : CommandClass.Neutral;
    }

    private static bool ClassifySafe(string root, string[] tokens)
    {
        switch (root)
        {
            case "git":
                return IsSafeGit(tokens);
            case "find":
                return !tokens.Any(t => t is "-exec" or "-execdir" or "-ok" or "-okdir" or "-delete"
                    or "-fls" or "-fprint" or "-fprintf" or "-fprint0");
            case "sed":
                return tokens.Contains("-n") && !tokens.Any(t => t == "-i" || t.StartsWith("-i", StringComparison.Ordinal) || t == "--in-place");
            case "rg":
                return !tokens.Any(t => t.StartsWith("--pre", StringComparison.Ordinal)
                    || t is "--hostname-bin" or "-z" or "--search-zip");
            case "awk":
                return false; // awk can run system()
            default:
                return s_safeRoots.Contains(root);
        }
    }

    private static bool IsSafeGit(string[] tokens)
    {
        // Reject global flags that can execute arbitrary code (git -c core.pager=..., --exec-path, etc.).
        if (tokens.Any(t => t is "-c" or "--config-env" or "--exec-path" or "-p" or "--paginate"))
        {
            return false;
        }

        var sub = tokens.Skip(1).FirstOrDefault(t => !t.StartsWith('-'));
        if (sub is null)
        {
            return false;
        }

        return sub is "status" or "log" or "diff" or "show" or "branch" or "remote" or "rev-parse"
            or "describe" or "blame" or "tag" or "ls-files" or "ls-remote" or "shortlog" or "reflog"
            or "whatchanged" or "cat-file" or "for-each-ref" or "rev-list" or "name-rev" or "symbolic-ref";
    }

    private static string LeafName(string token)
    {
        var slash = token.LastIndexOf('/');
        var name = slash >= 0 ? token[(slash + 1)..] : token;
        return name;
    }
}
