using Andy.Permissions.Authorization;
using Andy.Permissions.Execution;
using Andy.Permissions.Model;
using Andy.Permissions.Prompt;
using Andy.Tools.Core;
using Xunit;

namespace Andy.Permissions.Tests;

public class PermissionedToolExecutorTests
{
    private static PermissionedToolExecutor Build(ListPermissionStore store, FakeInnerExecutor inner, IPermissionPrompt prompt) =>
        new(inner, new ToolPermissionAuthorizer(store, new DefaultToolActionResolver()), prompt, store, registry: null);

    private static ToolExecutionContext Ctx() => new() { CorrelationId = "corr1" };

    private static Dictionary<string, object?> P(params (string, object?)[] kv) => kv.ToDictionary(x => x.Item1, x => x.Item2);

    [Fact]
    public async Task Allow_delegates_to_inner_without_prompting()
    {
        var store = new ListPermissionStore(); // no rule, null metadata ⇒ fallback Allow
        var inner = new FakeInnerExecutor();
        var prompt = new RecordingPrompt(PermissionDecision.DenyOnce);
        var sut = Build(store, inner, prompt);

        var result = await sut.ExecuteAsync("read_file", P(("file_path", "/x")), Ctx());

        Assert.True(result.IsSuccessful);
        Assert.Equal(1, inner.ExecuteCount);
        Assert.Equal(0, prompt.CallCount);
    }

    [Fact]
    public async Task Deny_short_circuits_inner_and_reports_violation()
    {
        var store = new ListPermissionStore().Add("read_file(/etc/**)", PermissionOutcome.Deny, PermissionLayer.Builtin);
        var inner = new FakeInnerExecutor { ThrowIfExecuted = true };
        var prompt = new RecordingPrompt(PermissionDecision.AllowOnce);
        var sut = Build(store, inner, prompt);

        SecurityViolationEventArgs? raised = null;
        sut.SecurityViolation += (_, e) => raised = e;

        var result = await sut.ExecuteAsync("read_file", P(("file_path", "/etc/passwd")), Ctx());

        Assert.False(result.IsSuccessful);
        Assert.NotEmpty(result.SecurityViolations);
        Assert.Equal("read_file", result.ToolId);
        Assert.Equal("corr1", result.CorrelationId);
        Assert.Equal(0, inner.ExecuteCount);
        Assert.Equal(0, prompt.CallCount); // Deny never prompts
        Assert.NotNull(raised);
    }

    [Fact]
    public async Task Ask_then_allow_runs_inner_once_with_one_prompt()
    {
        var store = new ListPermissionStore().Add("write_file(*)", PermissionOutcome.Ask, PermissionLayer.User);
        var inner = new FakeInnerExecutor();
        var prompt = new RecordingPrompt(PermissionDecision.AllowOnce);
        var sut = Build(store, inner, prompt);

        var result = await sut.ExecuteAsync("write_file", P(("file_path", "/tmp/x")), Ctx());

        Assert.True(result.IsSuccessful);
        Assert.Equal(1, inner.ExecuteCount);
        Assert.Equal(1, prompt.CallCount);
    }

    [Fact]
    public async Task Ask_then_deny_blocks_inner()
    {
        var store = new ListPermissionStore().Add("write_file(*)", PermissionOutcome.Ask, PermissionLayer.User);
        var inner = new FakeInnerExecutor { ThrowIfExecuted = true };
        var prompt = new RecordingPrompt(PermissionDecision.DenyOnce);
        var sut = Build(store, inner, prompt);

        var result = await sut.ExecuteAsync("write_file", P(("file_path", "/tmp/x")), Ctx());

        Assert.False(result.IsSuccessful);
        Assert.Equal(0, inner.ExecuteCount);
        Assert.Equal(1, prompt.CallCount);
    }

    [Fact]
    public async Task Allow_always_persists_so_second_call_does_not_prompt()
    {
        var store = new ListPermissionStore().Add("write_file(*)", PermissionOutcome.Ask, PermissionLayer.User);
        var inner = new FakeInnerExecutor();
        var prompt = new RecordingPrompt(new PermissionDecision(Allowed: true, Persist: PersistScope.User));
        var sut = Build(store, inner, prompt);

        await sut.ExecuteAsync("write_file", P(("file_path", "/tmp/x")), Ctx());
        await sut.ExecuteAsync("write_file", P(("file_path", "/tmp/x")), Ctx());

        Assert.Equal(2, inner.ExecuteCount);
        Assert.Equal(1, prompt.CallCount); // remembered after the first
    }

    [Fact]
    public async Task Both_overloads_are_gated()
    {
        var store = new ListPermissionStore().Add("read_file(/etc/**)", PermissionOutcome.Deny, PermissionLayer.Builtin);
        var inner = new FakeInnerExecutor { ThrowIfExecuted = true };
        var sut = Build(store, inner, new RecordingPrompt(PermissionDecision.AllowOnce));

        var viaRequest = await sut.ExecuteAsync(new ToolExecutionRequest
        {
            ToolId = "read_file",
            Parameters = P(("file_path", "/etc/passwd")),
            Context = Ctx(),
        });

        var viaArgs = await sut.ExecuteAsync("read_file", P(("file_path", "/etc/passwd")), Ctx());

        Assert.False(viaRequest.IsSuccessful);
        Assert.False(viaArgs.IsSuccessful);
        Assert.Equal(0, inner.ExecuteCount);
    }

    [Fact]
    public async Task Cancellation_during_prompt_denies_without_throwing()
    {
        var store = new ListPermissionStore().Add("write_file(*)", PermissionOutcome.Ask, PermissionLayer.User);
        var inner = new FakeInnerExecutor { ThrowIfExecuted = true };
        var prompt = new FuncPrompt(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return PermissionDecision.AllowOnce;
        });
        var sut = Build(store, inner, prompt);

        using var cts = new CancellationTokenSource();
        var ctx = new ToolExecutionContext { CorrelationId = "c", CancellationToken = cts.Token };
        var task = sut.ExecuteAsync("write_file", P(("file_path", "/tmp/x")), ctx);
        cts.CancelAfter(20);

        var result = await task; // should not throw
        Assert.False(result.IsSuccessful);
        Assert.Equal(0, inner.ExecuteCount);
    }

    [Fact]
    public void Forwards_non_execute_members_and_reraises_events()
    {
        var store = new ListPermissionStore();
        var inner = new FakeInnerExecutor();
        var sut = Build(store, inner, new RecordingPrompt(PermissionDecision.AllowOnce));

        var started = 0;
        var completed = 0;
        var violations = 0;
        sut.ExecutionStarted += (_, _) => started++;
        sut.ExecutionCompleted += (_, _) => completed++;
        sut.SecurityViolation += (_, _) => violations++;

        inner.RaiseAll();

        Assert.Equal(1, started);
        Assert.Equal(1, completed);
        Assert.Equal(1, violations);
        Assert.Empty(sut.GetRunningExecutions());
    }
}
