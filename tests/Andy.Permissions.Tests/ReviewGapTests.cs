using System.Collections.ObjectModel;
using Andy.Permissions.Authorization;
using Andy.Permissions.Execution;
using Andy.Permissions.Model;
using Andy.Permissions.Prompt;
using Andy.Permissions.Store;
using Andy.Tools.Core;
using Xunit;

namespace Andy.Permissions.Tests;

/// <summary>
/// Regression tests for the epic #5 review gaps: immutable snapshots (#9), persistence cancellation and
/// tool-id validation (#8), managed-layer default discovery (#7), and the documented permission modes (#6).
/// </summary>
public sealed class ReviewGapTests : IDisposable
{
    private readonly string _dir;

    public ReviewGapTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "andyreview-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private PermissionStoreOptions HermeticOptions() => new()
    {
        UserFilePath = Path.Combine(_dir, "user.json"),
        ProjectFilePath = null,
        LocalFilePath = null,
        ManagedFilePath = null,
        Builtin = Array.Empty<PermissionRule>(),
    };

    // ---- #9: immutable GetRules() snapshots -------------------------------------------------------

    [Fact]
    public void GetRules_returns_immutable_snapshot_that_cannot_be_cast_to_a_mutable_list()
    {
        File.WriteAllText(Path.Combine(_dir, "user.json"), """{ "allow": ["read_file(/u/**)"] }""");
        var store = new FilePermissionStore(HermeticOptions());
        var rules = store.GetRules();

        Assert.IsType<ReadOnlyCollection<PermissionRule>>(rules);
        Assert.Throws<InvalidCastException>(() => (List<PermissionRule>)rules);
        Assert.Throws<NotSupportedException>(() =>
            ((IList<PermissionRule>)rules).Add(PermissionRule.Parse("write_file(*)", PermissionOutcome.Allow, PermissionLayer.User)));

        // The store's effective policy is untouched by the mutation attempts.
        Assert.Single(store.GetRules());
    }

    [Fact]
    public async Task GetRules_snapshot_is_stable_after_a_later_append()
    {
        var store = new FilePermissionStore(HermeticOptions());
        var before = store.GetRules();
        Assert.Empty(before);

        await store.AppendRuleAsync("write_file", "/tmp/x", PermissionOutcome.Allow, PersistScope.User);

        Assert.Empty(before);                 // old snapshot is frozen
        Assert.NotEmpty(store.GetRules());     // fresh snapshot reflects the append
    }

    // ---- #8: persistence cancellation -------------------------------------------------------------

    [Fact]
    public async Task Canceled_file_persistence_does_not_append_a_rule()
    {
        var store = new FilePermissionStore(HermeticOptions());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.AppendRuleAsync("write_file", "/tmp/x", PermissionOutcome.Allow, PersistScope.User, cts.Token));

        Assert.DoesNotContain(store.GetRules(), r => r.Tool == "write_file");
        var reopened = new FilePermissionStore(HermeticOptions());
        Assert.DoesNotContain(reopened.GetRules(), r => r.Tool == "write_file");
    }

    [Fact]
    public async Task Canceled_session_persistence_does_not_add_a_rule()
    {
        var store = new FilePermissionStore(HermeticOptions());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.AppendRuleAsync("read_file", "/x", PermissionOutcome.Allow, PersistScope.Session, cts.Token));

        Assert.Empty(store.GetRules());
    }

    // ---- #8: tool-id validation -------------------------------------------------------------------

    [Theory]
    [InlineData("Bad-Tool")]
    [InlineData("UPPER")]
    [InlineData("1tool")]
    [InlineData("_tool")]
    [InlineData("has space")]
    [InlineData("")]
    public void AppendRuleAsync_rejects_invalid_tool_ids(string toolId)
    {
        var store = new FilePermissionStore(HermeticOptions());

        // Tool-id validation is argument validation: it throws synchronously, before any Task is created,
        // so Assert.Throws (not ThrowsAsync) is correct here despite the Task-returning signature.
#pragma warning disable xUnit2014
        Assert.Throws<ArgumentException>(() =>
        {
            store.AppendRuleAsync(toolId, "/x", PermissionOutcome.Allow, PersistScope.User);
        });
#pragma warning restore xUnit2014
    }

    [Theory]
    [InlineData("read_file")]
    [InlineData("execute_command")]
    [InlineData("http_request2")]
    [InlineData("*")]
    public async Task AppendRuleAsync_accepts_valid_tool_ids(string toolId)
    {
        var store = new FilePermissionStore(HermeticOptions());
        await store.AppendRuleAsync(toolId, "/x", PermissionOutcome.Allow, PersistScope.User);
        Assert.Contains(store.GetRules(), r => r.Tool == toolId);
    }

    [Fact]
    public void Loading_a_file_skips_invalid_tool_ids_without_throwing()
    {
        File.WriteAllText(Path.Combine(_dir, "user.json"),
            """{ "allow": ["Bad-Tool(/x)", "read_file(/ok/**)", "1nope(/y)"] }""");

        var store = new FilePermissionStore(HermeticOptions());
        var rules = store.GetRules();

        Assert.Single(rules);
        Assert.Contains(rules, r => r.Tool == "read_file" && r.Specifier == "/ok/**");
    }

    [Fact]
    public void PermissionRule_Parse_rejects_invalid_tool_ids()
    {
        Assert.Throws<FormatException>(() => PermissionRule.Parse("Bad-Tool(x)", PermissionOutcome.Allow, PermissionLayer.User));
        Assert.Throws<FormatException>(() => PermissionRule.Parse("UPPER", PermissionOutcome.Allow, PermissionLayer.User));
        Assert.False(PermissionRule.IsValidToolId("Bad-Tool"));
        Assert.True(PermissionRule.IsValidToolId("read_file"));
        Assert.True(PermissionRule.IsValidToolId("*"));
    }

    // ---- #7: managed-layer default discovery ------------------------------------------------------

    [Fact]
    public void Default_options_enable_managed_layer_discovery()
    {
        var options = new PermissionStoreOptions();
        Assert.False(string.IsNullOrEmpty(options.ManagedFilePath));
        Assert.Equal(PermissionStoreOptions.DefaultManagedFilePath(), options.ManagedFilePath);
    }

    [Fact]
    public void DefaultManagedFilePath_is_platform_appropriate()
    {
        var path = PermissionStoreOptions.DefaultManagedFilePath();
        if (OperatingSystem.IsWindows())
        {
            Assert.EndsWith(Path.Combine("andy", "permissions.managed.json"), path);
        }
        else
        {
            Assert.Equal("/etc/andy/permissions.managed.json", path);
        }
    }

    [Fact]
    public void Missing_managed_file_yields_no_rules_and_does_not_throw()
    {
        var options = HermeticOptions();
        options.ManagedFilePath = Path.Combine(_dir, "does-not-exist.managed.json");

        var store = new FilePermissionStore(options);
        Assert.DoesNotContain(store.GetRules(), r => r.Layer == PermissionLayer.Managed);
    }

    [Fact]
    public void Discovered_managed_deny_is_absolute_over_a_user_allow()
    {
        var managed = Path.Combine(_dir, "policy.managed.json");
        File.WriteAllText(managed, """{ "deny": ["execute_command(*)"] }""");
        File.WriteAllText(Path.Combine(_dir, "user.json"), """{ "allow": ["execute_command(*)"] }""");

        var options = HermeticOptions();
        options.ManagedFilePath = managed;

        var store = new FilePermissionStore(options);
        var auth = new ToolPermissionAuthorizer(store, new DefaultToolActionResolver());
        var ctx = new ToolAuthorizationContext("execute_command",
            new Dictionary<string, object?> { ["command"] = "npm run deploy" });

        Assert.Equal(PermissionOutcome.Deny, auth.Evaluate(ctx).Outcome);
    }

    // ---- #6: permission modes ---------------------------------------------------------------------

    [Theory]
    [InlineData(null, PermissionMode.FailClosed)]
    [InlineData("", PermissionMode.FailClosed)]
    [InlineData("garbage", PermissionMode.FailClosed)]
    [InlineData("fail-closed", PermissionMode.FailClosed)]
    [InlineData("default", PermissionMode.Default)]
    [InlineData("plan", PermissionMode.Plan)]
    [InlineData("accept-edits", PermissionMode.AcceptEdits)]
    [InlineData("accept_edits", PermissionMode.AcceptEdits)]
    [InlineData("ACCEPT-EDITS", PermissionMode.AcceptEdits)]
    [InlineData("bypass", PermissionMode.Bypass)]
    [InlineData("yolo", PermissionMode.Bypass)]
    [InlineData("YOLO", PermissionMode.Bypass)]
    public void ParseMode_maps_documented_mode_names(string? value, PermissionMode expected)
    {
        Assert.Equal(expected, NonInteractivePermissionPrompt.ParseMode(value));
    }

    [Theory]
    [InlineData(PermissionMode.FailClosed, false)]
    [InlineData(PermissionMode.Default, false)]
    [InlineData(PermissionMode.Plan, false)]
    [InlineData(PermissionMode.AcceptEdits, true)]  // a file-path Ask is an in-scope edit
    [InlineData(PermissionMode.Bypass, true)]
    public void ResolveAsk_for_a_file_path_ask(PermissionMode mode, bool expectedAllowed)
    {
        var request = AskRequest(new ResourceAccess(ResourceKind.Path, "/workspace/a.txt"));
        Assert.Equal(expectedAllowed, NonInteractivePermissionPrompt.ResolveAsk(mode, request).Allowed);
    }

    [Theory]
    [InlineData(PermissionMode.AcceptEdits, false)] // a command Ask is NOT a file edit
    [InlineData(PermissionMode.Bypass, true)]
    [InlineData(PermissionMode.FailClosed, false)]
    public void ResolveAsk_for_a_command_ask(PermissionMode mode, bool expectedAllowed)
    {
        var request = AskRequest(new ResourceAccess(ResourceKind.Command, "npm run deploy"));
        Assert.Equal(expectedAllowed, NonInteractivePermissionPrompt.ResolveAsk(mode, request).Allowed);
    }

    [Fact]
    public void AcceptEdits_denies_a_mixed_or_empty_ask()
    {
        var mixed = AskRequest(
            new ResourceAccess(ResourceKind.Path, "/workspace/a.txt"),
            new ResourceAccess(ResourceKind.Host, "example.com"));
        Assert.False(NonInteractivePermissionPrompt.ResolveAsk(PermissionMode.AcceptEdits, mixed).Allowed);

        var empty = new PermissionRequest("t", "t", "s", new PermissionEvaluation(PermissionOutcome.Ask, []));
        Assert.False(NonInteractivePermissionPrompt.ResolveAsk(PermissionMode.AcceptEdits, empty).Allowed);
    }

    [Theory]
    [InlineData(PermissionMode.FailClosed)]
    [InlineData(PermissionMode.Default)]
    [InlineData(PermissionMode.Plan)]
    [InlineData(PermissionMode.AcceptEdits)]
    [InlineData(PermissionMode.Bypass)]
    public async Task No_mode_can_override_a_deny(PermissionMode mode)
    {
        var store = new ListPermissionStore().Add("write_file(*)", PermissionOutcome.Deny, PermissionLayer.Managed);
        var gate = Gate(store, mode);

        var verdict = await gate.CheckAsync(new ToolPermissionGateRequest
        {
            ToolId = "write_file",
            Parameters = new Dictionary<string, object?> { ["file_path"] = "/workspace/a.txt" },
            Context = new ToolExecutionContext(),
        });

        Assert.False(verdict.Allowed);
    }

    [Theory]
    [InlineData(PermissionMode.AcceptEdits, true)]
    [InlineData(PermissionMode.Bypass, true)]
    [InlineData(PermissionMode.Plan, false)]
    [InlineData(PermissionMode.Default, false)]
    [InlineData(PermissionMode.FailClosed, false)]
    public async Task Mode_resolves_a_file_edit_ask_through_the_gate(PermissionMode mode, bool expectedAllowed)
    {
        var store = new ListPermissionStore().Add("write_file(*)", PermissionOutcome.Ask, PermissionLayer.Managed);
        var gate = Gate(store, mode);

        var verdict = await gate.CheckAsync(new ToolPermissionGateRequest
        {
            ToolId = "write_file",
            Parameters = new Dictionary<string, object?> { ["file_path"] = "/workspace/a.txt" },
            Context = new ToolExecutionContext(),
        });

        Assert.Equal(expectedAllowed, verdict.Allowed);
    }

    private static ToolPermissionGate Gate(IPermissionStore store, PermissionMode mode) =>
        new(new ToolPermissionAuthorizer(store, new DefaultToolActionResolver()),
            new NonInteractivePermissionPrompt(mode),
            store);

    private static PermissionRequest AskRequest(params ResourceAccess[] asked) =>
        new("tool", "tool", "summary",
            new PermissionEvaluation(PermissionOutcome.Ask,
                asked.Select(a => new EvaluatedResource(a, PermissionOutcome.Ask, null)).ToList()));
}
