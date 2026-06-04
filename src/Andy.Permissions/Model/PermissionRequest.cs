namespace Andy.Permissions.Model;

/// <summary>
/// A consent request handed to an <see cref="Andy.Permissions.Prompt.IPermissionPrompt"/>. Designed to be
/// serializable (plain strings + records) so a future remote broker can ship it out of a container and
/// receive a <see cref="PermissionDecision"/> back (§5 / Phase 4).
/// </summary>
/// <param name="ToolId">The tool being invoked.</param>
/// <param name="ToolDisplayName">A human-friendly tool name for the prompt, if known.</param>
/// <param name="ActionSummary">A short human-readable description of what the tool will do.</param>
/// <param name="Evaluation">The full evaluation breakdown, so the UI can show which resource forced the Ask.</param>
public sealed record PermissionRequest(
    string ToolId,
    string? ToolDisplayName,
    string ActionSummary,
    PermissionEvaluation Evaluation);
