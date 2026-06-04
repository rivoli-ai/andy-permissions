using System.Text;
using System.Text.RegularExpressions;

namespace Andy.Permissions.Matching;

/// <summary>
/// One independently-authorizable command found in a shell line, after wrapper unwrapping.
/// </summary>
/// <param name="Command">The effective command string (wrappers/env-prefixes stripped, <c>bash -c</c> unwrapped).</param>
/// <param name="HasRedirection">True if the original segment contained an output redirection (exfiltration risk).</param>
public readonly record struct BashSegment(string Command, bool HasRedirection);

/// <summary>
/// The result of splitting a shell command line into independently-authorizable command segments.
/// </summary>
/// <param name="Segments">Every executable command found, including those inside substitutions and shell wrappers.</param>
/// <param name="ParsedCleanly">
/// False when the input could not be tokenized safely (unbalanced quotes/substitution, unterminated
/// heredoc, NUL byte, excessive nesting). The authorizer treats this as "force at least Ask" (RD7).
/// </param>
public readonly record struct BashSplitResult(IReadOnlyList<BashSegment> Segments, bool ParsedCleanly);

/// <summary>
/// Splits a shell command line into the individual commands it would run, so each can be authorized
/// independently — <c>git status &amp;&amp; rm -rf /</c> must NOT inherit <c>git status</c>'s allow. It is a
/// security boundary: anything it cannot parse confidently is reported as <see cref="BashSplitResult.ParsedCleanly"/>
/// false rather than silently dropping a command (fail closed). It also unwraps <c>bash -c "..."</c> and
/// strips benign process wrappers (<c>timeout</c>, <c>nice</c>, <c>env</c>, …) so the real command is the
/// one evaluated, and flags output redirection.
/// </summary>
public static class BashCommandSplitter
{
    private const int MaxDepth = 25;

    private static readonly Regex s_heredocOpener =
        new(@"<<-?\s*(['""]?)([A-Za-z_][A-Za-z0-9_]*)\1", RegexOptions.Compiled);

    // A shell function definition (incl. the classic fork bomb ":(){ :|:& };:") cannot be authorized by
    // command prefix, so we treat its presence as "not parsed cleanly" and fail closed.
    private static readonly Regex s_functionDefinition =
        new(@"[\w:.\-]+\s*\(\)\s*\{", RegexOptions.Compiled);

    private static readonly HashSet<string> s_shells =
        new(StringComparer.OrdinalIgnoreCase) { "bash", "sh", "zsh", "dash", "ksh" };

    // Benign wrappers whose presence shouldn't change which command is being authorized.
    // sudo and xargs are intentionally NOT stripped (sudo must stay visible to the dangerous-command
    // classifier; xargs feeds arbitrary commands).
    private static readonly HashSet<string> s_benignWrappers =
        new(StringComparer.Ordinal) { "nohup", "time", "env", "timeout", "nice", "stdbuf", "ionice" };

    /// <summary>Splits a command line into authorizable segments.</summary>
    public static BashSplitResult Split(string command) => Split(command, depth: 0);

    private static BashSplitResult Split(string command, int depth)
    {
        if (command is null || command.IndexOf('\0') >= 0 || depth > MaxDepth)
        {
            return new BashSplitResult(Array.Empty<BashSegment>(), false);
        }

        var clean = true;
        var withoutHeredocs = StripHeredocBodies(command, ref clean);

        if (s_functionDefinition.IsMatch(withoutHeredocs))
        {
            clean = false; // shell function / fork-bomb definitions are not prefix-authorizable
        }

        var raw = new List<string>();
        ScanLevel(withoutHeredocs, depth, raw, ref clean);

        var segments = new List<BashSegment>();
        foreach (var rawSegment in raw)
        {
            var trimmed = rawSegment.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }

            Normalize(trimmed, depth, segments, ref clean);
        }

        return new BashSplitResult(segments, clean);
    }

    /// <summary>
    /// Turns one raw segment into one or more effective <see cref="BashSegment"/>s: detect redirection,
    /// strip leading env assignments and benign wrappers, and recursively unwrap <c>bash -c "..."</c>.
    /// </summary>
    private static void Normalize(string rawSegment, int depth, List<BashSegment> into, ref bool clean)
    {
        var hasRedirection = HasUnquotedRedirection(rawSegment);
        var effective = StripLeadingAssignments(rawSegment);
        effective = StripBenignWrappers(effective);

        var tokens = TokenizeWords(effective);
        if (tokens.Count >= 3 && s_shells.Contains(LeafName(tokens[0])))
        {
            var inner = ExtractDashCArgument(tokens);
            if (inner is not null)
            {
                var innerResult = Split(inner, depth + 1);
                if (!innerResult.ParsedCleanly)
                {
                    clean = false;
                }

                if (innerResult.Segments.Count > 0)
                {
                    foreach (var seg in innerResult.Segments)
                    {
                        into.Add(seg with { HasRedirection = seg.HasRedirection || hasRedirection });
                    }

                    return;
                }
            }
        }

        into.Add(new BashSegment(effective, hasRedirection));
    }

    /// <summary>Returns the <c>-c</c> argument of a shell invocation, or null if there isn't one.</summary>
    private static string? ExtractDashCArgument(IReadOnlyList<string> tokens)
    {
        for (var i = 1; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (t == "-c" || t == "-lc" || t == "-cl")
            {
                return i + 1 < tokens.Count ? tokens[i + 1] : null;
            }

            // Combined flags like -lc handled above; a bare flag bundle containing 'c' at the end.
            if (t.Length > 1 && t[0] == '-' && t[^1] == 'c' && t.All(c => char.IsLetter(c) || c == '-'))
            {
                return i + 1 < tokens.Count ? tokens[i + 1] : null;
            }
        }

        return null;
    }

    private static string StripBenignWrappers(string command)
    {
        var changed = true;
        while (changed)
        {
            changed = false;
            var tokens = TokenizeWords(command);
            if (tokens.Count == 0)
            {
                break;
            }

            var head = LeafName(tokens[0]);
            if (!s_benignWrappers.Contains(head))
            {
                break;
            }

            var idx = 1;
            switch (head)
            {
                case "nohup":
                case "time":
                    break; // just drop the wrapper word
                case "env":
                    while (idx < tokens.Count && Regex.IsMatch(tokens[idx], @"^[A-Za-z_][A-Za-z0-9_]*="))
                    {
                        idx++;
                    }

                    break;
                default: // timeout / nice / stdbuf / ionice: skip options and the leading numeric/duration arg
                    while (idx < tokens.Count && (tokens[idx].StartsWith('-') || IsDurationOrNumber(tokens[idx])))
                    {
                        idx++;
                    }

                    break;
            }

            if (idx >= tokens.Count)
            {
                break; // nothing left to run; leave as-is so it doesn't vanish
            }

            command = string.Join(' ', tokens.Skip(idx));
            changed = true;
        }

        return command;
    }

    private static bool IsDurationOrNumber(string token) =>
        Regex.IsMatch(token, @"^\d+(\.\d+)?[smhd]?$");

    private static string LeafName(string token)
    {
        var slash = token.LastIndexOf('/');
        return slash >= 0 ? token[(slash + 1)..] : token;
    }

    /// <summary>True if the segment contains an unquoted output-redirection operator.</summary>
    private static bool HasUnquotedRedirection(string segment)
    {
        for (var i = 0; i < segment.Length; i++)
        {
            var c = segment[i];
            if (c == '\\')
            {
                i++;
                continue;
            }

            if (c == '\'')
            {
                var end = segment.IndexOf('\'', i + 1);
                if (end < 0) { return false; }
                i = end;
                continue;
            }

            if (c == '"')
            {
                var end = segment.IndexOf('"', i + 1);
                if (end < 0) { return false; }
                i = end;
                continue;
            }

            if (c == '>')
            {
                return true; // >, >>, &>, 2> all start with or contain '>'
            }
        }

        return false;
    }

    /// <summary>Tokenizes a command into whitespace-separated words, unquoting and respecting escapes.</summary>
    private static List<string> TokenizeWords(string command)
    {
        var words = new List<string>();
        var sb = new StringBuilder();
        var inWord = false;

        for (var i = 0; i < command.Length; i++)
        {
            var c = command[i];
            if (char.IsWhiteSpace(c))
            {
                if (inWord) { words.Add(sb.ToString()); sb.Clear(); inWord = false; }
                continue;
            }

            inWord = true;
            switch (c)
            {
                case '\\' when i + 1 < command.Length:
                    sb.Append(command[++i]);
                    break;
                case '\'':
                    {
                        var end = command.IndexOf('\'', i + 1);
                        if (end < 0) { sb.Append(command.AsSpan(i + 1)); i = command.Length; }
                        else { sb.Append(command, i + 1, end - i - 1); i = end; }

                        break;
                    }
                case '"':
                    {
                        var end = FindClosingDoubleQuote(command, i);
                        if (end < 0) { sb.Append(command.AsSpan(i + 1)); i = command.Length; }
                        else { sb.Append(command, i + 1, end - i - 1); i = end; }

                        break;
                    }
                default:
                    sb.Append(c);
                    break;
            }
        }

        if (inWord) { words.Add(sb.ToString()); }

        return words;
    }

    private static int FindClosingDoubleQuote(string s, int open)
    {
        for (var i = open + 1; i < s.Length; i++)
        {
            if (s[i] == '\\') { i++; continue; }
            if (s[i] == '"') { return i; }
        }

        return -1;
    }

    /// <summary>
    /// Removes heredoc bodies so operators inside them (<c>cat &lt;&lt;EOF ... &amp;&amp; ... EOF</c>) are not
    /// mistaken for command separators. Sets <paramref name="clean"/> false on an unterminated heredoc.
    /// </summary>
    private static string StripHeredocBodies(string command, ref bool clean)
    {
        if (!command.Contains("<<", StringComparison.Ordinal))
        {
            return command;
        }

        var lines = command.Replace("\r\n", "\n").Split('\n');
        var output = new StringBuilder();
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            output.Append(line).Append('\n');

            var matches = s_heredocOpener.Matches(line);
            if (matches.Count == 0)
            {
                continue;
            }

            foreach (Match m in matches)
            {
                var delim = m.Groups[2].Value;
                var stripTabs = line.Contains("<<-", StringComparison.Ordinal);
                var found = false;
                while (++i < lines.Length)
                {
                    var bodyLine = lines[i];
                    var probe = stripTabs ? bodyLine.TrimStart('\t') : bodyLine;
                    if (probe.Trim() == delim)
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    clean = false;
                    break;
                }
            }
        }

        return output.ToString();
    }

    /// <summary>Scans one nesting level, splitting on top-level operators while respecting quoting and recursing into substitutions.</summary>
    private static void ScanLevel(string text, int depth, List<string> segments, ref bool clean)
    {
        if (depth > MaxDepth)
        {
            clean = false;
            return;
        }

        var current = new StringBuilder();
        var i = 0;
        while (i < text.Length)
        {
            var c = text[i];

            if (c == '\\' && i + 1 < text.Length)
            {
                current.Append(c).Append(text[i + 1]);
                i += 2;
                continue;
            }

            if (c == '\'')
            {
                var end = text.IndexOf('\'', i + 1);
                if (end < 0)
                {
                    clean = false;
                    current.Append(text[i..]);
                    break;
                }

                current.Append(text, i, end - i + 1);
                i = end + 1;
                continue;
            }

            if (c == '"')
            {
                var consumed = ConsumeDoubleQuoted(text, i, depth, segments, ref clean);
                current.Append(text, i, consumed);
                i += consumed;
                continue;
            }

            if (c == '`')
            {
                var end = text.IndexOf('`', i + 1);
                if (end < 0)
                {
                    clean = false;
                    current.Append(text[i..]);
                    break;
                }

                ScanLevel(text[(i + 1)..end], depth + 1, segments, ref clean);
                current.Append(text, i, end - i + 1);
                i = end + 1;
                continue;
            }

            if ((c == '$' && i + 1 < text.Length && text[i + 1] == '(')
                || ((c == '<' || c == '>') && i + 1 < text.Length && text[i + 1] == '('))
            {
                var open = i + 1;
                var close = FindMatchingParen(text, open);
                if (close < 0)
                {
                    clean = false;
                    current.Append(text[i..]);
                    break;
                }

                ScanLevel(text[(open + 1)..close], depth + 1, segments, ref clean);
                current.Append(text, i, close - i + 1);
                i = close + 1;
                continue;
            }

            if (c == '#' && (current.Length == 0 || char.IsWhiteSpace(current[^1])))
            {
                var nl = text.IndexOf('\n', i);
                if (nl < 0)
                {
                    break;
                }

                i = nl;
                continue;
            }

            if (c == '&' && i + 1 < text.Length && text[i + 1] == '&')
            {
                Flush(current, segments);
                i += 2;
                continue;
            }

            if (c == '|' && i + 1 < text.Length && text[i + 1] == '|')
            {
                Flush(current, segments);
                i += 2;
                continue;
            }

            if (c is ';' or '|' or '&' or '\n')
            {
                Flush(current, segments);
                i++;
                continue;
            }

            if (c is '(' or ')' or '{' or '}')
            {
                Flush(current, segments);
                i++;
                continue;
            }

            current.Append(c);
            i++;
        }

        Flush(current, segments);
    }

    private static int ConsumeDoubleQuoted(string text, int start, int depth, List<string> segments, ref bool clean)
    {
        var i = start + 1;
        while (i < text.Length)
        {
            var c = text[i];
            if (c == '\\' && i + 1 < text.Length)
            {
                i += 2;
                continue;
            }

            if (c == '"')
            {
                return i - start + 1;
            }

            if (c == '`')
            {
                var end = text.IndexOf('`', i + 1);
                if (end < 0)
                {
                    break;
                }

                ScanLevel(text[(i + 1)..end], depth + 1, segments, ref clean);
                i = end + 1;
                continue;
            }

            if (c == '$' && i + 1 < text.Length && text[i + 1] == '(')
            {
                var close = FindMatchingParen(text, i + 1);
                if (close < 0)
                {
                    break;
                }

                ScanLevel(text[(i + 2)..close], depth + 1, segments, ref clean);
                i = close + 1;
                continue;
            }

            i++;
        }

        clean = false;
        return text.Length - start;
    }

    private static int FindMatchingParen(string text, int openParen)
    {
        var depth = 0;
        for (var i = openParen; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '\\' && i + 1 < text.Length)
            {
                i++;
                continue;
            }

            if (c == '\'')
            {
                var end = text.IndexOf('\'', i + 1);
                if (end < 0)
                {
                    return -1;
                }

                i = end;
                continue;
            }

            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }
        }

        return -1;
    }

    private static void Flush(StringBuilder current, List<string> segments)
    {
        var s = current.ToString().Trim();
        if (s.Length > 0)
        {
            segments.Add(s);
        }

        current.Clear();
    }

    /// <summary>
    /// Strips leading <c>VAR=value</c> environment assignments so the effective command is matched
    /// (<c>FOO=bar git status</c> ⇒ <c>git status</c>). The assignment's value is still scanned for
    /// substitutions during the main pass, so <c>FOO=$(curl evil)</c> still surfaces <c>curl evil</c>.
    /// </summary>
    private static string StripLeadingAssignments(string segment)
    {
        var rest = segment;
        while (true)
        {
            var m = Regex.Match(rest, @"^[A-Za-z_][A-Za-z0-9_]*=(\S*)\s+(?=\S)");
            if (!m.Success)
            {
                return rest;
            }

            rest = rest[m.Length..];
        }
    }
}
