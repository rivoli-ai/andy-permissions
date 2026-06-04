using Andy.Tools.Core;

namespace Andy.Permissions.Model;

/// <summary>
/// Everything the authorizer needs to evaluate a tool call. Kept separate from
/// <see cref="ToolExecutionContext"/> so the authorizer is unit-testable without constructing a full
/// executor context.
/// </summary>
/// <param name="ToolId">The snake_case tool id being invoked.</param>
/// <param name="Parameters">The tool call parameters (used to resolve governed resources).</param>
/// <param name="WorkingDirectory">
/// The working directory used to resolve relative path specifiers; null falls back to the process CWD.
/// </param>
/// <param name="Metadata">
/// The tool's metadata, used for the no-rule fallback (RequiresConfirmation / dangerous capabilities ⇒
/// Ask). Null ⇒ the fallback treats the tool as benign (Allow).
/// </param>
public sealed record ToolAuthorizationContext(
    string ToolId,
    IReadOnlyDictionary<string, object?> Parameters,
    string? WorkingDirectory = null,
    ToolMetadata? Metadata = null);
