using System.Text;
using System.Text.RegularExpressions;

namespace Andy.Permissions.Matching;

/// <summary>
/// The result of splitting a shell command line into independently-authorizable command segments.
/// </summary>
/// <param name="Segments">Every executable command found, including those inside substitutions.</param>
/// <param name="ParsedCleanly">
/// False when the input could not be tokenized safely (unbalanced quotes/substitution, unterminated
/// heredoc, NUL byte, excessive nesting). The authorizer treats this as "force at least Ask" (RD7).
/// </param>
public readonly record struct BashSplitResult(IReadOnlyList<string> Segments, bool ParsedCleanly);

/// <summary>
/// Splits a shell command line into the individual commands it would run, so each can be authorized
/// independently — <c>git status &amp;&amp; rm -rf /</c> must NOT inherit <c>git status</c>'s allow. It is a
/// security boundary: anything it cannot parse confidently is reported as <see cref="BashSplitResult.ParsedCleanly"/>
/// false rather than silently dropping a command (fail closed).
/// </summary>
public static class BashCommandSplitter
{
    private const int MaxDepth = 25;

    private static readonly Regex s_heredocOpener =
        new(@"<<-?\s*(['""]?)([A-Za-z_][A-Za-z0-9_]*)\1", RegexOptions.Compiled);

    /// <summary>Splits a command line into authorizable segments.</summary>
    public static BashSplitResult Split(string command)
    {
        if (command is null || command.IndexOf('\0') >= 0)
        {
            return new BashSplitResult(Array.Empty<string>(), false);
        }

        var clean = true;
        var withoutHeredocs = StripHeredocBodies(command, ref clean);

        var segments = new List<string>();
        ScanLevel(withoutHeredocs, depth: 0, segments, ref clean);

        var cleaned = segments
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToList();

        return new BashSplitResult(cleaned, clean);
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

            // Consume body lines until each delimiter is seen (handle multiple openers on one line).
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

    /// <summary>
    /// Scans one nesting level, splitting on top-level operators while respecting quoting and recursing
    /// into command substitutions.
    /// </summary>
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

            // Backslash escape (outside single quotes; handled inline below for quotes).
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

            // Command/process substitution: $( ... ), <( ... ), >( ... )
            if ((c == '$' && i + 1 < text.Length && text[i + 1] == '(')
                || ((c == '<' || c == '>') && i + 1 < text.Length && text[i + 1] == '('))
            {
                var open = c == '$' ? i + 1 : i + 1;
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

            // Comment: '#' at a word boundary runs to end of line.
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

            // Operators that separate commands.
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

            // Brace/subshell group delimiters: treat as separators (their contents are still commands).
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

    /// <summary>
    /// Consumes a double-quoted span starting at <paramref name="start"/> (the opening quote), recursing
    /// into any substitutions inside it. Returns the number of characters consumed (including both quotes,
    /// or to end-of-string if unterminated, in which case <paramref name="clean"/> is set false).
    /// </summary>
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

    /// <summary>Finds the index of the ')' matching the '(' at <paramref name="openParen"/>, or -1.</summary>
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
            segments.Add(StripLeadingAssignments(s));
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
