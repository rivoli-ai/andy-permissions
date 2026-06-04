using System.Globalization;

namespace Andy.Permissions.Model;

/// <summary>
/// A single permission rule, e.g. <c>read_file(./secrets/**)</c> with outcome Deny. The textual form
/// is <c>toolId(specifier)</c>; a bare <c>toolId</c> is shorthand for <c>toolId(*)</c>. The outcome is
/// determined by which list (allow/ask/deny) the rule lives in, not embedded in the text (RD1).
/// </summary>
public sealed class PermissionRule
{
    /// <summary>The snake_case tool id this rule applies to, or <c>*</c> for any tool (RD1).</summary>
    public required string Tool { get; init; }

    /// <summary>The resource specifier (path glob, command prefix, <c>domain:host</c>, or <c>*</c>).</summary>
    public required string Specifier { get; init; }

    /// <summary>The outcome this rule grants when it matches.</summary>
    public required PermissionOutcome Outcome { get; init; }

    /// <summary>The layer this rule was loaded from (drives precedence; not serialized).</summary>
    public PermissionLayer Layer { get; init; } = PermissionLayer.Session;

    /// <summary>
    /// Specificity score for tie-breaking within a layer: the count of non-wildcard characters in the
    /// specifier (longer literal = more specific). A bare tool match (<c>*</c>) scores 0.
    /// </summary>
    public int Specificity => Specifier.Count(c => c is not ('*' or '?'));

    /// <summary>True when this rule applies to every tool (<see cref="Tool"/> == <c>*</c>).</summary>
    public bool MatchesAnyTool => Tool == "*";

    /// <summary>
    /// Parses a rule from its textual form. <paramref name="text"/> may be <c>toolId(specifier)</c> or a
    /// bare <c>toolId</c> (⇒ specifier <c>*</c>). Throws <see cref="FormatException"/> on malformed input.
    /// </summary>
    public static PermissionRule Parse(string text, PermissionOutcome outcome, PermissionLayer layer)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new FormatException("Permission rule text is empty.");
        }

        var trimmed = text.Trim();
        var open = trimmed.IndexOf('(');
        if (open < 0)
        {
            // Bare tool id ⇒ matches any resource for that tool.
            return new PermissionRule { Tool = trimmed, Specifier = "*", Outcome = outcome, Layer = layer };
        }

        if (!trimmed.EndsWith(')'))
        {
            throw new FormatException($"Permission rule '{text}' has '(' without a closing ')'.");
        }

        var tool = trimmed[..open].Trim();
        if (tool.Length == 0)
        {
            throw new FormatException($"Permission rule '{text}' is missing a tool id before '('.");
        }

        // Specifier is everything between the first '(' and the LAST ')', so specifiers may themselves
        // contain parentheses (e.g. a command or a path with parens).
        var specifier = trimmed[(open + 1)..^1];
        if (specifier.Length == 0)
        {
            specifier = "*";
        }

        return new PermissionRule { Tool = tool, Specifier = specifier, Outcome = outcome, Layer = layer };
    }

    /// <summary>Tries to parse a rule, returning false instead of throwing on malformed input.</summary>
    public static bool TryParse(string text, PermissionOutcome outcome, PermissionLayer layer, out PermissionRule? rule)
    {
        try
        {
            rule = Parse(text, outcome, layer);
            return true;
        }
        catch (FormatException)
        {
            rule = null;
            return false;
        }
    }

    /// <summary>Formats the rule back into its <c>toolId(specifier)</c> textual form.</summary>
    public string Format() =>
        string.Create(CultureInfo.InvariantCulture, $"{Tool}({Specifier})");

    /// <inheritdoc />
    public override string ToString() => $"{Format()} => {Outcome} [{Layer}]";
}
