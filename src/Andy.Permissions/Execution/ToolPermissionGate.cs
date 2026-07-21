using Andy.Permissions.Authorization;
using Andy.Permissions.Model;
using Andy.Permissions.Prompt;
using Andy.Permissions.Store;
using Andy.Tools.Core;

namespace Andy.Permissions.Execution;

/// <summary>
/// The canonical consent gate: implements <see cref="IToolPermissionGate"/> so it can be consulted
/// directly by <c>Andy.Tools</c>' <c>ToolExecutor</c> (Phase 5). Evaluates the call against the rules
/// (RD2); Allow ⇒ allowed; Deny ⇒ denied; Ask ⇒ consult the prompt under a serialization lock with a
/// re-check (RD4), persisting "always" decisions. Returns a single <see cref="ToolPermissionVerdict"/>.
/// </summary>
public sealed class ToolPermissionGate : IToolPermissionGate
{
    private readonly IToolPermissionAuthorizer _authorizer;
    private readonly IPermissionPrompt _prompt;
    private readonly IPermissionStore _store;
    private readonly SemaphoreSlim _promptGate = new(1, 1);

    public ToolPermissionGate(IToolPermissionAuthorizer authorizer, IPermissionPrompt prompt, IPermissionStore store)
    {
        _authorizer = authorizer ?? throw new ArgumentNullException(nameof(authorizer));
        _prompt = prompt ?? throw new ArgumentNullException(nameof(prompt));
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <inheritdoc />
    public async Task<ToolPermissionVerdict> CheckAsync(ToolPermissionGateRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var authContext = new ToolAuthorizationContext(
            request.ToolId,
            request.Parameters,
            request.Context?.WorkingDirectory,
            request.Metadata);

        var evaluation = _authorizer.Evaluate(authContext);
        if (evaluation.Outcome == PermissionOutcome.Allow)
        {
            return ToolPermissionVerdict.Allow;
        }

        if (evaluation.Outcome == PermissionOutcome.Deny)
        {
            return Denied(request.ToolId, evaluation);
        }

        // Ask — serialize prompts and re-check under the lock (RD4).
        await _promptGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            evaluation = _authorizer.Evaluate(authContext);
            if (evaluation.Outcome == PermissionOutcome.Allow)
            {
                return ToolPermissionVerdict.Allow;
            }

            if (evaluation.Outcome == PermissionOutcome.Deny)
            {
                return Denied(request.ToolId, evaluation);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                return Denied(request.ToolId, evaluation, "cancelled before consent");
            }

            PermissionDecision decision;
            try
            {
                decision = await _prompt.RequestAsync(BuildRequest(request.ToolId, evaluation), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return Denied(request.ToolId, evaluation, "consent cancelled");
            }

            try
            {
                await PersistAsync(request.ToolId, evaluation, decision, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Persistence was canceled mid-flight; the decision was validly obtained, so honor it for
                // this call without remembering it. The store guarantees nothing was written (#8).
            }

            if (decision.Allowed)
            {
                return ToolPermissionVerdict.Allow;
            }

            return Denied(request.ToolId, evaluation,
                string.IsNullOrWhiteSpace(decision.Feedback) ? "denied by consent" : $"denied by consent: {decision.Feedback}");
        }
        finally
        {
            _promptGate.Release();
        }
    }

    private async Task PersistAsync(string toolId, PermissionEvaluation evaluation, PermissionDecision decision, CancellationToken ct)
    {
        if (decision.Persist == PersistScope.Once)
        {
            return;
        }

        var outcome = decision.Allowed ? PermissionOutcome.Allow : PermissionOutcome.Deny;
        foreach (var resource in evaluation.Resources.Where(r => r.Outcome == PermissionOutcome.Ask))
        {
            await _store.AppendRuleAsync(toolId, ToSpecifier(resource.Access), outcome, decision.Persist, ct).ConfigureAwait(false);
        }
    }

    private static string ToSpecifier(ResourceAccess access) => access.Kind switch
    {
        ResourceKind.Command => $"{access.Value}:*",
        ResourceKind.Host => $"domain:{access.Value}",
        ResourceKind.Path => access.Value,
        _ => "*",
    };

    private static PermissionRequest BuildRequest(string toolId, PermissionEvaluation evaluation)
    {
        var asked = evaluation.Resources.Where(r => r.Outcome == PermissionOutcome.Ask).ToList();
        var summary = asked.Count == 0
            ? $"{toolId} requires permission"
            : $"{toolId}: " + string.Join(", ", asked.Select(r => $"{r.Access.Kind} '{r.Access.Value}'"));
        return new PermissionRequest(toolId, toolId, summary, evaluation);
    }

    private static ToolPermissionVerdict Denied(string toolId, PermissionEvaluation evaluation, string? extra = null)
    {
        var offending = evaluation.Resources.FirstOrDefault(r => r.Outcome == PermissionOutcome.Deny)
                        ?? evaluation.Resources.FirstOrDefault(r => r.Outcome == PermissionOutcome.Ask);
        var detail = offending is null ? string.Empty : $" ({offending.Access.Kind} '{offending.Access.Value}')";
        var reason = $"Tool '{toolId}' blocked by permission policy{detail}"
                     + (extra is null ? string.Empty : $": {extra}");
        return ToolPermissionVerdict.Deny(reason);
    }
}
