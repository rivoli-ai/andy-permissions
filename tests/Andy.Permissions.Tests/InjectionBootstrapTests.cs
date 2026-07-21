using Andy.Permissions.Authorization;
using Andy.Permissions.DependencyInjection;
using Andy.Permissions.Execution;
using Andy.Permissions.Model;
using Andy.Permissions.Prompt;
using Andy.Tools.Core;
using Xunit;

namespace Andy.Permissions.Tests;

public sealed class InjectionBootstrapTests : IDisposable
{
    private readonly string _dir;

    public InjectionBootstrapTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "andyinj-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void File_source_takes_precedence_over_json()
    {
        var file = Path.Combine(_dir, "inj.json");
        File.WriteAllText(file, """{ "allow": ["read_file(/from-file/**)"] }""");

        string? Env(string k) => k switch
        {
            PermissionInjectionBootstrap.FileEnvVar => file,
            PermissionInjectionBootstrap.JsonEnvVar => """{ "allow": ["read_file(/from-json/**)"] }""",
            _ => null,
        };

        var rules = PermissionInjectionBootstrap.ResolveInjectedRules(Env, _ => false);
        Assert.Contains(rules, r => r.Specifier == "/from-file/**");
        Assert.DoesNotContain(rules, r => r.Specifier == "/from-json/**");
    }

    [Fact]
    public void Json_source_used_when_no_file()
    {
        string? Env(string k) => k == PermissionInjectionBootstrap.JsonEnvVar
            ? """{ "deny": ["bash_command(rm:*)"] }"""
            : null;

        var rules = PermissionInjectionBootstrap.ResolveInjectedRules(Env, _ => false);
        Assert.Contains(rules, r => r.Tool == "bash_command" && r.Outcome == PermissionOutcome.Deny && r.Layer == PermissionLayer.Injected);
    }

    [Theory]
    [InlineData(null, PermissionMode.FailClosed)]
    [InlineData("", PermissionMode.FailClosed)]
    [InlineData("garbage", PermissionMode.FailClosed)]
    [InlineData("bypass", PermissionMode.Bypass)]
    [InlineData("BYPASS", PermissionMode.Bypass)]
    public void Mode_defaults_to_fail_closed(string? value, PermissionMode expected)
    {
        string? Env(string k) => k == PermissionInjectionBootstrap.ModeEnvVar ? value : null;
        Assert.Equal(expected, PermissionInjectionBootstrap.ResolveMode(Env));
    }

    [Fact]
    public async Task Injected_allow_rules_yield_zero_prompts_in_container_scenario()
    {
        // The headline guarantee: inject up front ⇒ inner runs, prompt never called (RD9 / §12.7).
        var store = new Store.FilePermissionStore(new Store.PermissionStoreOptions
        {
            UserFilePath = null,
            ManagedFilePath = null,
            Builtin = Array.Empty<PermissionRule>(),
        });
        store.SetInjectedRules(
        [
            PermissionRule.Parse("read_file(*)", PermissionOutcome.Allow, PermissionLayer.Injected),
            PermissionRule.Parse("write_file(*)", PermissionOutcome.Allow, PermissionLayer.Injected),
            PermissionRule.Parse("bash_command(*)", PermissionOutcome.Allow, PermissionLayer.Injected),
        ]);

        var inner = new FakeInnerExecutor();
        var prompt = new RecordingPrompt(PermissionDecision.DenyOnce); // would block if ever consulted
        var sut = new PermissionedToolExecutor(
            inner,
            new ToolPermissionAuthorizer(store, new DefaultToolActionResolver()),
            prompt,
            store,
            registry: null);

        await sut.ExecuteAsync("read_file", new Dictionary<string, object?> { ["file_path"] = "/tmp/a" });
        await sut.ExecuteAsync("write_file", new Dictionary<string, object?> { ["file_path"] = "/tmp/b" });
        await sut.ExecuteAsync("bash_command", new Dictionary<string, object?> { ["command"] = "echo hi && ls" });

        Assert.Equal(3, inner.ExecuteCount);
        Assert.Equal(0, prompt.CallCount);
    }
}
