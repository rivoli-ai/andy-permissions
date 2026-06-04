using System.Text.Json;
using System.Text.Json.Serialization;
using Andy.Permissions.Model;

namespace Andy.Permissions.Store;

/// <summary>
/// The on-disk JSON shape of a permission layer file, mirroring Claude Code's
/// <c>settings.json#permissions</c> (<c>allow</c>/<c>ask</c>/<c>deny</c> arrays of <c>tool(specifier)</c>
/// strings) for muscle-memory compatibility.
/// </summary>
public sealed class RuleSetDocument
{
    [JsonPropertyName("allow")]
    public List<string> Allow { get; set; } = [];

    [JsonPropertyName("ask")]
    public List<string> Ask { get; set; } = [];

    [JsonPropertyName("deny")]
    public List<string> Deny { get; set; } = [];

    private static readonly JsonSerializerOptions s_readOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private static readonly JsonSerializerOptions s_writeOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    /// <summary>
    /// Parses the rules from a file into <see cref="PermissionRule"/>s tagged with <paramref name="layer"/>.
    /// Resilient: a missing/empty/corrupt file or individual malformed rule strings yield the rules that
    /// could be parsed (never throws), so one bad file can't brick a run (§12.6).
    /// </summary>
    public static IReadOnlyList<PermissionRule> LoadFromFile(string? path, PermissionLayer layer)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            return Array.Empty<PermissionRule>();
        }

        string json;
        try
        {
            json = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Array.Empty<PermissionRule>();
        }

        return LoadFromJson(json, layer);
    }

    /// <summary>
    /// Parses rules from a JSON string into <see cref="PermissionRule"/>s tagged with <paramref name="layer"/>.
    /// Resilient: empty/whitespace/corrupt JSON yields an empty list (never throws). Used for the injected
    /// container layer (<c>ANDY_PERMISSIONS_JSON</c>) as well as file layers.
    /// </summary>
    public static IReadOnlyList<PermissionRule> LoadFromJson(string? json, PermissionLayer layer)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Array.Empty<PermissionRule>();
        }

        RuleSetDocument? doc;
        try
        {
            doc = JsonSerializer.Deserialize<RuleSetDocument>(json, s_readOptions);
        }
        catch (JsonException)
        {
            return Array.Empty<PermissionRule>();
        }

        if (doc is null)
        {
            return Array.Empty<PermissionRule>();
        }

        var rules = new List<PermissionRule>();
        AddParsed(rules, doc.Allow, PermissionOutcome.Allow, layer);
        AddParsed(rules, doc.Ask, PermissionOutcome.Ask, layer);
        AddParsed(rules, doc.Deny, PermissionOutcome.Deny, layer);
        return rules;
    }

    private static void AddParsed(List<PermissionRule> into, List<string>? texts, PermissionOutcome outcome, PermissionLayer layer)
    {
        if (texts is null)
        {
            return;
        }

        foreach (var text in texts)
        {
            if (PermissionRule.TryParse(text, outcome, layer, out var rule) && rule is not null)
            {
                into.Add(rule);
            }
        }
    }

    /// <summary>Reads a document from disk for mutation, returning an empty one if absent/corrupt.</summary>
    public static RuleSetDocument ReadForWrite(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                if (!string.IsNullOrWhiteSpace(json))
                {
                    return JsonSerializer.Deserialize<RuleSetDocument>(json, s_readOptions) ?? new RuleSetDocument();
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // Fall through to a fresh document; we don't want to lose the new rule over a corrupt file.
        }

        return new RuleSetDocument();
    }

    /// <summary>Adds a rule string to the list matching the outcome, de-duplicating.</summary>
    public void Add(string ruleText, PermissionOutcome outcome)
    {
        var list = outcome switch
        {
            PermissionOutcome.Allow => Allow,
            PermissionOutcome.Ask => Ask,
            _ => Deny,
        };

        if (!list.Contains(ruleText, StringComparer.Ordinal))
        {
            list.Add(ruleText);
        }
    }

    /// <summary>Serializes to indented JSON.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, s_writeOptions);
}
