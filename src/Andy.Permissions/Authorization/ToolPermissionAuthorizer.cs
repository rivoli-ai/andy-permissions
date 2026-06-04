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
                            var segAccess = new ResourceAccess(ResourceKind.Command, segment);
                            evaluations.Add(EvaluateResource(segAccess, toolRules, context, split.ParsedCleanly));
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
        bool parsedCleanly)
    {
        var matching = toolRules
            .Where(r => SpecifierMatcher.MatchesResource(r.Specifier, access, context.WorkingDirectory))
            .ToList();

        PermissionOutcome outcome;
        PermissionRule? matched;

        var denies = matching.Where(r => r.Outcome == PermissionOutcome.Deny).ToList();
        if (denies.Count > 0)
        {
            // Deny is absolute regardless of layer (RD2 step 3 / RD8).
            matched = MostAuthoritative(denies);
            outcome = PermissionOutcome.Deny;
        }
        else if (matching.Count > 0)
        {
            matched = MostAuthoritative(matching);
            outcome = matched.Outcome;
        }
        else
        {
            matched = null;
            outcome = FallbackOutcome(context.Metadata);
        }

        // RD7: a command we couldn't parse cleanly can never be silently Allowed.
        if (!parsedCleanly && outcome == PermissionOutcome.Allow)
        {
            outcome = PermissionOutcome.Ask;
        }

        return new EvaluatedResource(access, outcome, matched, parsedCleanly);
    }

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
