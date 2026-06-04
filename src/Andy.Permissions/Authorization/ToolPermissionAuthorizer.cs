using Andy.Permissions.Matching;
using Andy.Permissions.Model;
using Andy.Permissions.Store;
using Andy.Tools.Core;

namespace Andy.Permissions.Authorization;

/// <summary>
/// Default authorizer implementing the RD2 precedence model: Deny is absolute across all layers; otherwise
/// the highest-precedence matching layer wins (most-specific specifier breaks ties); otherwise a
/// metadata-driven fallback. Bash commands are decomposed so each segment is authorized independently
/// (RD7), and outcomes combine as Deny &gt; Ask &gt; Allow.
/// </summary>
public sealed class ToolPermissionAuthorizer : IToolPermissionAuthorizer
{
    private readonly IPermissionStore _store;
    private readonly IToolActionResolver _resolver;

    public ToolPermissionAuthorizer(IPermissionStore store, IToolActionResolver resolver)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
    }

    /// <inheritdoc />
    public PermissionEvaluation Evaluate(ToolAuthorizationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var toolRules = _store.GetRules()
            .Where(r => SpecifierMatcher.MatchesTool(r.Tool, context.ToolId))
            .ToList();

        var resources = _resolver.Resolve(context.ToolId, context.Parameters);
        var evaluations = new List<EvaluatedResource>();

        if (resources.Count == 0)
        {
            // No governed resource: decide from tool-id rules (specifier "*") + metadata fallback.
            var none = new ResourceAccess(ResourceKind.None, string.Empty);
            evaluations.Add(EvaluateResource(none, toolRules, context, parsedCleanly: true));
        }
        else
        {
            foreach (var resource in resources)
            {
                if (resource.Kind == ResourceKind.Command)
                {
                    var split = BashCommandSplitter.Split(resource.Value);
                    if (split.Segments.Count == 0)
                    {
                        evaluations.Add(EvaluateResource(resource, toolRules, context, split.ParsedCleanly));
                    }
                    else
                    {
                        foreach (var segment in split.Segments)
                        {
                            var segAccess = new ResourceAccess(ResourceKind.Command, segment.Command);
                            evaluations.Add(EvaluateResource(segAccess, toolRules, context, split.ParsedCleanly, segment.HasRedirection));
                        }
                    }
                }
                else
                {
                    evaluations.Add(EvaluateResource(resource, toolRules, context, parsedCleanly: true));
                }
            }
        }

        return new PermissionEvaluation(Combine(evaluations), evaluations);
    }

    private static EvaluatedResource EvaluateResource(
        ResourceAccess access,
        IReadOnlyList<PermissionRule> toolRules,
        ToolAuthorizationContext context,
        bool parsedCleanly,
        bool hasRedirection = false)
    {
        var literalMatches = toolRules
            .Where(r => SpecifierMatcher.MatchesResource(r.Specifier, access, context.WorkingDirectory))
            .ToList();

        // Symlink-aware Deny: a deny also matches if the path's real (resolved) target matches it, so a
        // symlink inside an allowed directory can't be used to reach a denied secret.
        var denies = literalMatches.Where(r => r.Outcome == PermissionOutcome.Deny).ToList();
        if (access.Kind == ResourceKind.Path)
        {
            var realPath = SpecifierMatcher.ResolveRealPath(access.Value, context.WorkingDirectory);
            if (realPath is not null)
            {
                foreach (var rule in toolRules)
                {
                    if (rule.Outcome == PermissionOutcome.Deny
                        && !literalMatches.Contains(rule)
                        && SpecifierMatcher.MatchPath(rule.Specifier, realPath, workingDirectory: null))
                    {
                        denies.Add(rule);
                    }
                }
            }
        }

        PermissionOutcome outcome;
        PermissionRule? matched;

        if (denies.Count > 0)
        {
            // Deny is absolute regardless of layer (RD2 step 3 / RD8).
            matched = MostAuthoritative(denies);
            outcome = PermissionOutcome.Deny;
        }
        else if (literalMatches.Count > 0)
        {
            matched = MostAuthoritative(literalMatches);
            outcome = matched.Outcome;
        }
        else
        {
            matched = null;
            outcome = FallbackOutcome(context.Metadata);
        }

        if (access.Kind == ResourceKind.Command && outcome != PermissionOutcome.Deny)
        {
            outcome = ApplyCommandHeuristics(access.Value, outcome, matched, hasRedirection);
        }

        // RD7: a command we couldn't parse cleanly can never be silently Allowed.
        if (!parsedCleanly && outcome == PermissionOutcome.Allow)
        {
            outcome = PermissionOutcome.Ask;
        }

        return new EvaluatedResource(access, outcome, matched, parsedCleanly);
    }

    /// <summary>
    /// Applies command classification and redirection downgrade (spec §2.4/§2.5): known-safe read-only
    /// commands auto-Allow on fallback; dangerous commands and redirections raise a floor of Ask over a
    /// <em>broad</em> allow (a specific allow rule for the exact command is still honored).
    /// </summary>
    private static PermissionOutcome ApplyCommandHeuristics(
        string command, PermissionOutcome outcome, PermissionRule? matched, bool hasRedirection)
    {
        var cls = CommandClassifier.Classify(command);

        // Fallback (no explicit rule) for a known-safe read-only command ⇒ Allow instead of Ask.
        if (matched is null && cls == CommandClass.KnownSafeReadOnly && outcome == PermissionOutcome.Ask)
        {
            outcome = PermissionOutcome.Allow;
        }

        var broadAllow = outcome == PermissionOutcome.Allow && IsBroad(matched);

        if (cls == CommandClass.Dangerous && broadAllow)
        {
            outcome = PermissionOutcome.Ask; // dangerous commands need confirmation unless specifically allowed
        }
        else if (hasRedirection && broadAllow)
        {
            outcome = PermissionOutcome.Ask; // output redirection is an exfiltration risk
        }

        return outcome;
    }

    /// <summary>A match is "broad" if it came from the fallback or a wildcard/any-tool rule.</summary>
    private static bool IsBroad(PermissionRule? matched) =>
        matched is null || matched.Specifier == "*" || matched.MatchesAnyTool;

    /// <summary>Highest layer wins; most-specific specifier breaks ties within a layer (RD2 step 4).</summary>
    private static PermissionRule MostAuthoritative(IEnumerable<PermissionRule> rules) =>
        rules.OrderByDescending(r => (int)r.Layer)
             .ThenByDescending(r => r.Specificity)
             .First();

    private static PermissionOutcome FallbackOutcome(ToolMetadata? metadata)
    {
        if (metadata is null)
        {
            return PermissionOutcome.Allow;
        }

        if (metadata.RequiresConfirmation)
        {
            return PermissionOutcome.Ask;
        }

        var caps = metadata.RequiredCapabilities;
        if (caps.HasFlag(ToolCapability.Destructive)
            || caps.HasFlag(ToolCapability.Elevated)
            || caps.HasFlag(ToolCapability.ProcessExecution))
        {
            return PermissionOutcome.Ask;
        }

        return PermissionOutcome.Allow;
    }

    private static PermissionOutcome Combine(IReadOnlyList<EvaluatedResource> evaluations)
    {
        if (evaluations.Count == 0)
        {
            return PermissionOutcome.Allow;
        }

        if (evaluations.Any(e => e.Outcome == PermissionOutcome.Deny))
        {
            return PermissionOutcome.Deny;
        }

        if (evaluations.Any(e => e.Outcome == PermissionOutcome.Ask))
        {
            return PermissionOutcome.Ask;
        }

        return PermissionOutcome.Allow;
    }
}
