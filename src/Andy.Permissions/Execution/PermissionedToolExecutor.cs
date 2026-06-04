using Andy.Permissions.Authorization;
using Andy.Permissions.Model;
using Andy.Permissions.Prompt;
using Andy.Permissions.Store;
using Andy.Tools.Core;

namespace Andy.Permissions.Execution;

/// <summary>
/// An <see cref="IToolExecutor"/> decorator that gates every execution through the permission authorizer
/// (RD2) before delegating to the inner executor. Allow ⇒ delegate; Deny ⇒ synthesize a failure
/// <see cref="ToolExecutionResult"/> (RD3, the agent can adapt); Ask ⇒ consult the prompt under a
/// serialization lock with a re-check (RD4). Implements the full <see cref="IToolExecutor"/> surface,
/// forwarding non-execute members and re-raising the inner's events (RD6).
/// </summary>
public sealed class PermissionedToolExecutor : IToolExecutor
{
    private readonly IToolExecutor _inner;
    private readonly IToolPermissionAuthorizer _authorizer;
    private readonly IPermissionPrompt _prompt;
    private readonly IPermissionStore _store;
    private readonly IToolRegistry? _registry;
    private readonly SemaphoreSlim _promptGate = new(1, 1);

    public PermissionedToolExecutor(
        IToolExecutor inner,
        IToolPermissionAuthorizer authorizer,
        IPermissionPrompt prompt,
        IPermissionStore store,
        IToolRegistry? registry = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _authorizer = authorizer ?? throw new ArgumentNullException(nameof(authorizer));
        _prompt = prompt ?? throw new ArgumentNullException(nameof(prompt));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _registry = registry;

        _inner.ExecutionStarted += (_, e) => ExecutionStarted?.Invoke(this, e);
        _inner.ExecutionCompleted += (_, e) => ExecutionCompleted?.Invoke(this, e);
        _inner.SecurityViolation += (_, e) => SecurityViolation?.Invoke(this, e);
    }

    public event EventHandler<ToolExecutionStartedEventArgs>? ExecutionStarted;
    public event EventHandler<ToolExecutionCompletedEventArgs>? ExecutionCompleted;
    public event EventHandler<SecurityViolationEventArgs>? SecurityViolation;

    /// <inheritdoc />
    public async Task<ToolExecutionResult> ExecuteAsync(ToolExecutionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var gate = await GateAsync(request.ToolId, request.Parameters, request.Context, request.Context.CancellationToken)
            .ConfigureAwait(false);
        return gate ?? await _inner.ExecuteAsync(request).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ToolExecutionResult> ExecuteAsync(string toolId, Dictionary<string, object?> parameters, ToolExecutionContext? context = null)
    {
        var ct = context?.CancellationToken ?? CancellationToken.None;
        var gate = await GateAsync(toolId, parameters, context, ct).ConfigureAwait(false);
        return gate ?? await _inner.ExecuteAsync(toolId, parameters, context).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs the consent gate. Returns null when the call may proceed to the inner executor, or a
    /// synthesized failure result when it is denied.
    /// </summary>
    private async Task<ToolExecutionResult?> GateAsync(
        string toolId,
        IReadOnlyDictionary<string, object?> parameters,
        ToolExecutionContext? context,
        CancellationToken cancellationToken)
    {
        var authContext = new ToolAuthorizationContext(
            toolId,
            parameters,
            context?.WorkingDirectory,
            _registry?.GetTool(toolId)?.Metadata);

        var evaluation = _authorizer.Evaluate(authContext);

        if (evaluation.Outcome == PermissionOutcome.Allow)
        {
            return null;
        }

        if (evaluation.Outcome == PermissionOutcome.Deny)
        {
            return Denied(toolId, context, evaluation);
        }

        // Ask — serialize prompts and re-check under the lock (RD4).
        await _promptGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            evaluation = _authorizer.Evaluate(authContext);
            if (evaluation.Outcome == PermissionOutcome.Allow)
            {
                return null;
            }

            if (evaluation.Outcome == PermissionOutcome.Deny)
            {
                return Denied(toolId, context, evaluation);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                return Denied(toolId, context, evaluation, "cancelled before consent");
            }

            PermissionDecision decision;
            try
            {
                var request = BuildRequest(toolId, evaluation);
                decision = await _prompt.RequestAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return Denied(toolId, context, evaluation, "consent cancelled");
            }

            await PersistAsync(toolId, evaluation, decision, cancellationToken).ConfigureAwait(false);

            return decision.Allowed ? null : Denied(toolId, context, evaluation, "denied by consent");
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
            var specifier = ToSpecifier(resource.Access);
            await _store.AppendRuleAsync(toolId, specifier, outcome, decision.Persist, ct).ConfigureAwait(false);
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

    private ToolExecutionResult Denied(string toolId, ToolExecutionContext? context, PermissionEvaluation evaluation, string? extra = null)
    {
        var correlationId = string.IsNullOrEmpty(context?.CorrelationId)
            ? Guid.NewGuid().ToString("N")[..8]
            : context!.CorrelationId;

        var offending = evaluation.Resources.FirstOrDefault(r => r.Outcome == PermissionOutcome.Deny)
                        ?? evaluation.Resources.FirstOrDefault(r => r.Outcome == PermissionOutcome.Ask);
        var detail = offending is null
            ? string.Empty
            : $" ({offending.Access.Kind} '{offending.Access.Value}')";
        var reason = $"Tool '{toolId}' blocked by permission policy{detail}"
                     + (extra is null ? string.Empty : $": {extra}");

        var result = new ToolExecutionResult
        {
            ToolId = toolId,
            CorrelationId = correlationId,
            IsSuccessful = false,
            ErrorMessage = reason,
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow,
            SecurityViolations = [reason],
        };

        SecurityViolation?.Invoke(this, new SecurityViolationEventArgs(toolId, correlationId, reason, SecurityViolationSeverity.High));
        ExecutionCompleted?.Invoke(this, new ToolExecutionCompletedEventArgs(result));
        return result;
    }

    // ---- Forwarded (non-execute) members ----------------------------------------------------

    /// <inheritdoc />
    public Task<IList<string>> ValidateExecutionRequestAsync(ToolExecutionRequest request) =>
        _inner.ValidateExecutionRequestAsync(request);

    /// <inheritdoc />
    public Task<ToolResourceUsage?> EstimateResourceUsageAsync(string toolId, Dictionary<string, object?> parameters) =>
        _inner.EstimateResourceUsageAsync(toolId, parameters);

    /// <inheritdoc />
    public Task<int> CancelExecutionsAsync(string correlationId) =>
        _inner.CancelExecutionsAsync(correlationId);

    /// <inheritdoc />
    public IReadOnlyList<RunningExecutionInfo> GetRunningExecutions() =>
        _inner.GetRunningExecutions();

    /// <inheritdoc />
    public ToolExecutionStatistics GetStatistics() =>
        _inner.GetStatistics();
}
