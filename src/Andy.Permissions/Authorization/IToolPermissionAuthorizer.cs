using Andy.Permissions.Model;

namespace Andy.Permissions.Authorization;

/// <summary>
/// Decides whether a tool call should be allowed, denied, or requires consent, by matching it against the
/// merged rule set. Pure and synchronous: no I/O, no prompting (the decorator handles Ask).
/// </summary>
public interface IToolPermissionAuthorizer
{
    /// <summary>Evaluates a tool call and returns the combined outcome plus per-resource breakdown.</summary>
    PermissionEvaluation Evaluate(ToolAuthorizationContext context);
}
