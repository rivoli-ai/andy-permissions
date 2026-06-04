using Andy.Permissions.Model;
using Andy.Permissions.Prompt;
using Andy.Permissions.Store;
using Andy.Tools.Core;

namespace Andy.Permissions.Tests;

/// <summary>A controllable in-memory <see cref="IPermissionStore"/> for unit tests.</summary>
internal sealed class ListPermissionStore : IPermissionStore
{
    private readonly List<PermissionRule> _rules = [];

    public List<(string Tool, string Specifier, PermissionOutcome Outcome, PersistScope Scope)> Appends { get; } = [];

    public ListPermissionStore Add(string text, PermissionOutcome outcome, PermissionLayer layer)
    {
        _rules.Add(PermissionRule.Parse(text, outcome, layer));
        return this;
    }

    public IReadOnlyList<PermissionRule> GetRules() => _rules.ToList();

    public Task AppendRuleAsync(string toolId, string specifier, PermissionOutcome outcome, PersistScope scope, CancellationToken cancellationToken = default)
    {
        Appends.Add((toolId, specifier, outcome, scope));
        if (scope != PersistScope.Once)
        {
            var layer = scope switch
            {
                PersistScope.Session => PermissionLayer.Session,
                PersistScope.Project => PermissionLayer.Project,
                PersistScope.Local => PermissionLayer.Local,
                _ => PermissionLayer.User,
            };
            _rules.Add(new PermissionRule { Tool = toolId, Specifier = specifier, Outcome = outcome, Layer = layer });
        }

        return Task.CompletedTask;
    }

    public void AddSessionRule(PermissionRule rule) => _rules.Add(rule);

    public void SetInjectedRules(IEnumerable<PermissionRule> rules)
    {
        _rules.RemoveAll(r => r.Layer == PermissionLayer.Injected);
        _rules.AddRange(rules);
    }
}

/// <summary>A fake inner executor recording calls; can be set to throw if executed (deny short-circuit test).</summary>
internal sealed class FakeInnerExecutor : IToolExecutor
{
    public int ExecuteCount;
    public bool ThrowIfExecuted;
    public List<string> ExecutedToolIds { get; } = [];

    public event EventHandler<ToolExecutionStartedEventArgs>? ExecutionStarted;
    public event EventHandler<ToolExecutionCompletedEventArgs>? ExecutionCompleted;
    public event EventHandler<SecurityViolationEventArgs>? SecurityViolation;

    public void RaiseAll()
    {
        ExecutionStarted?.Invoke(this, new ToolExecutionStartedEventArgs("x", "c", new ToolExecutionContext()));
        ExecutionCompleted?.Invoke(this, new ToolExecutionCompletedEventArgs(new ToolExecutionResult { ToolId = "x" }));
        SecurityViolation?.Invoke(this, new SecurityViolationEventArgs("x", "c", "v", SecurityViolationSeverity.Low));
    }

    public Task<ToolExecutionResult> ExecuteAsync(ToolExecutionRequest request) => Run(request.ToolId);

    public Task<ToolExecutionResult> ExecuteAsync(string toolId, Dictionary<string, object?> parameters, ToolExecutionContext? context = null) => Run(toolId);

    private Task<ToolExecutionResult> Run(string toolId)
    {
        if (ThrowIfExecuted)
        {
            throw new InvalidOperationException($"Inner executor must not run for '{toolId}' (deny should short-circuit).");
        }

        Interlocked.Increment(ref ExecuteCount);
        ExecutedToolIds.Add(toolId);
        return Task.FromResult(new ToolExecutionResult { ToolId = toolId, IsSuccessful = true, Data = "ok" });
    }

    public Task<IList<string>> ValidateExecutionRequestAsync(ToolExecutionRequest request) => Task.FromResult<IList<string>>(new List<string>());
    public Task<ToolResourceUsage?> EstimateResourceUsageAsync(string toolId, Dictionary<string, object?> parameters) => Task.FromResult<ToolResourceUsage?>(null);
    public Task<int> CancelExecutionsAsync(string correlationId) => Task.FromResult(0);
    public IReadOnlyList<RunningExecutionInfo> GetRunningExecutions() => Array.Empty<RunningExecutionInfo>();
    public ToolExecutionStatistics GetStatistics() => new();
}

/// <summary>A consent provider backed by a delegate (for cancellation / custom-behavior tests).</summary>
internal sealed class FuncPrompt : IPermissionPrompt
{
    private readonly Func<PermissionRequest, CancellationToken, Task<PermissionDecision>> _fn;
    public FuncPrompt(Func<PermissionRequest, CancellationToken, Task<PermissionDecision>> fn) => _fn = fn;
    public Task<PermissionDecision> RequestAsync(PermissionRequest request, CancellationToken cancellationToken = default) => _fn(request, cancellationToken);
}

/// <summary>A recording consent provider that returns a configured decision and tracks concurrency.</summary>
internal sealed class RecordingPrompt : IPermissionPrompt
{
    private readonly Func<PermissionRequest, PermissionDecision> _decide;
    private int _concurrent;

    public RecordingPrompt(PermissionDecision decision) : this(_ => decision) { }
    public RecordingPrompt(Func<PermissionRequest, PermissionDecision> decide) => _decide = decide;

    public int CallCount;
    public int MaxConcurrent;
    public List<PermissionRequest> Requests { get; } = [];

    public async Task<PermissionDecision> RequestAsync(PermissionRequest request, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref CallCount);
        var now = Interlocked.Increment(ref _concurrent);
        UpdateMax(now);
        try
        {
            await Task.Delay(15, cancellationToken).ConfigureAwait(false);
            lock (Requests) { Requests.Add(request); }
            return _decide(request);
        }
        finally
        {
            Interlocked.Decrement(ref _concurrent);
        }
    }

    private void UpdateMax(int candidate)
    {
        int prev;
        do { prev = MaxConcurrent; if (candidate <= prev) return; }
        while (Interlocked.CompareExchange(ref MaxConcurrent, candidate, prev) != prev);
    }
}
