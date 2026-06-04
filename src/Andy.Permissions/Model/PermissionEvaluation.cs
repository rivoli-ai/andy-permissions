namespace Andy.Permissions.Model;

/// <summary>
/// How a single <see cref="ResourceAccess"/> resolved against the rules, including which rule (if any)
/// decided it — surfaced to the prompt so it can explain <em>why</em> consent is needed (D3).
/// </summary>
/// <param name="Access">The resource that was evaluated.</param>
/// <param name="Outcome">The outcome for this resource.</param>
/// <param name="MatchedRule">The rule that decided the outcome, or null if it came from the metadata fallback.</param>
/// <param name="ParsedCleanly">
/// For <see cref="ResourceKind.Command"/> resources: whether the command segment was tokenized cleanly.
/// False forces at least <see cref="PermissionOutcome.Ask"/> (RD7).
/// </param>
public sealed record EvaluatedResource(
    ResourceAccess Access,
    PermissionOutcome Outcome,
    PermissionRule? MatchedRule,
    bool ParsedCleanly = true);

/// <summary>
/// The combined evaluation of a whole tool call: the overall <see cref="Outcome"/> plus the per-resource
/// breakdown. The overall outcome combines resources as Deny &gt; Ask &gt; Allow (RD2 step 6).
/// </summary>
/// <param name="Outcome">The combined outcome for the action.</param>
/// <param name="Resources">The per-resource evaluations (empty when the action governs no resource).</param>
public sealed record PermissionEvaluation(
    PermissionOutcome Outcome,
    IReadOnlyList<EvaluatedResource> Resources);
