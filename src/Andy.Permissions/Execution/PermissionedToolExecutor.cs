using Andy.Permissions.Authorization;
using Andy.Permissions.Prompt;
using Andy.Permissions.Store;
using Andy.Tools.Core;

namespace Andy.Permissions.Execution;

/// <summary>
/// An <see cref="IToolExecutor"/> decorator that gates every execution through a
/// <see cref="ToolPermissionGate"/> before delegating to the inner executor. Allow ⇒ delegate; Deny ⇒
/// synthesize a failure <see cref="ToolExecutionResult"/> (the agent can adapt). Implements the full
/// <see cref="IToolExecutor"/> surface, forwarding non-execute members and re-raising the inner's events.
/// </summary>
/// <remarks>
/// As of Phase 5, the preferred integration is to register a <see cref="IToolPermissionGate"/> and let
/// <c>Andy.Tools</c>' <c>ToolExecutor</c> call it directly. This decorator remains for hosts running an
/// executor that does not yet support the built-in gate.
/// </remarks>
public sealed class PermissionedToolExecutor : IToolExecutor
{
    private readonly IToolExecutor _inner;
    private readonly IToolPermissionGate _gate;
    private readonly IToolRegistry? _registry;

    public PermissionedToolExecutor(
        IToolExecutor inner,
        IToolPermissionAuthorizer authorizer,
        IPermissionPrompt prompt,
        IPermissionStore store,
        IToolRegistry? registry = null)
        : this(inner, new ToolPermissionGate(authorizer, prompt, store), registry)
    {
    }

    public PermissionedToolExecutor(IToolExecutor inner, IToolPermissionGate gate, IToolRegistry? registry = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _gate = gate ?? throw new ArgumentNullException(nameof(gate));
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

    /// <summary>Returns null to proceed, or a synthesized failure result when denied.</summary>
    private async Task<ToolExecutionResult?> GateAsync(
        string toolId,
        IReadOnlyDictionary<string, object?> parameters,
        ToolExecutionContext? context,
        CancellationToken cancellationToken)
    {
        var verdict = await _gate.CheckAsync(
            new ToolPermissionGateRequest
            {
                ToolId = toolId,
                Parameters = parameters,
                Context = context ?? new ToolExecutionContext(),
                Metadata = _registry?.GetTool(toolId)?.Metadata,
            },
            cancellationToken).ConfigureAwait(false);

        if (verdict.Allowed)
        {
            return null;
        }

        var correlationId = string.IsNullOrEmpty(context?.CorrelationId)
            ? Guid.NewGuid().ToString("N")[..8]
            : context!.CorrelationId;
        var reason = verdict.Reason ?? $"Tool '{toolId}' blocked by permission policy";

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
