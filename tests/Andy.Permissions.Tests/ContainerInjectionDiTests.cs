using Andy.Permissions.DependencyInjection;
using Andy.Permissions.Model;
using Andy.Permissions.Prompt;
using Andy.Tools.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Andy.Permissions.Tests;

/// <summary>
/// End-to-end container tests through the real <c>AddAndyPermissions</c> DI wiring + environment-driven
/// injection bootstrap (RD9), exercised via the registered <see cref="IToolPermissionGate"/> (the seam
/// Andy.Tools' ToolExecutor calls). Mutates process env, so these run in one non-parallel collection and
/// restore env in a finally.
/// </summary>
[CollectionDefinition("env-mutating", DisableParallelization = true)]
public sealed class EnvMutatingCollection { }

[Collection("env-mutating")]
public sealed class ContainerInjectionDiTests
{
    private static async Task WithEnv(string? json, string? mode, RecordingPrompt? prompt, Func<IToolPermissionGate, Task> body)
    {
        var prevJson = Environment.GetEnvironmentVariable(PermissionInjectionBootstrap.JsonEnvVar);
        var prevMode = Environment.GetEnvironmentVariable(PermissionInjectionBootstrap.ModeEnvVar);
        var prevFile = Environment.GetEnvironmentVariable(PermissionInjectionBootstrap.FileEnvVar);
        try
        {
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.FileEnvVar, null);
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.JsonEnvVar, json);
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.ModeEnvVar, mode);

            var services = new ServiceCollection();
            if (prompt is not null)
            {
                services.AddSingleton<IPermissionPrompt>(prompt);   // registered before AddAndyPermissions (TryAdd)
            }

            services.AddAndyPermissions(o => o.UserFilePath = null); // injection drives policy

            await using var sp = services.BuildServiceProvider();
            var gate = sp.GetRequiredService<IToolPermissionGate>();
            await body(gate);
        }
        finally
        {
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.JsonEnvVar, prevJson);
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.ModeEnvVar, prevMode);
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.FileEnvVar, prevFile);
        }
    }

    private static ToolPermissionGateRequest Req(string toolId, params (string, object?)[] kv) => new()
    {
        ToolId = toolId,
        Parameters = kv.ToDictionary(x => x.Item1, x => x.Item2),
        Context = new ToolExecutionContext(),
    };

    [Fact]
    public async Task Injected_allows_run_with_zero_prompts()
    {
        var json = """{ "allow": ["read_file(*)", "write_file(*)", "execute_command(*)"] }""";
        var prompt = new RecordingPrompt(PermissionDecision.DenyOnce); // would block if ever consulted
        await WithEnv(json, mode: null, prompt, async gate =>
        {
            Assert.True((await gate.CheckAsync(Req("read_file", ("file_path", "/tmp/a")))).Allowed);
            Assert.True((await gate.CheckAsync(Req("write_file", ("file_path", "/tmp/b")))).Allowed);
            Assert.True((await gate.CheckAsync(Req("execute_command", ("command", "ls -la")))).Allowed);

            Assert.Equal(0, prompt.CallCount); // inject first, never ask
        });
    }

    [Fact]
    public async Task Fail_closed_denies_uncovered_ask_without_a_tty()
    {
        var json = """{ "ask": ["execute_command(*)"] }""";
        await WithEnv(json, mode: null, prompt: null, body: async gate =>
        {
            var verdict = await gate.CheckAsync(Req("execute_command", ("command", "npm run deploy")));
            Assert.False(verdict.Allowed);
        });
    }

    [Fact]
    public async Task Bypass_allows_ask_but_still_respects_deny()
    {
        var json = """{ "ask": ["execute_command(*)"], "deny": ["execute_command(npm run deploy:*)"] }""";
        await WithEnv(json, mode: "bypass", prompt: null, body: async gate =>
        {
            Assert.True((await gate.CheckAsync(Req("execute_command", ("command", "npm run test")))).Allowed);
            Assert.False((await gate.CheckAsync(Req("execute_command", ("command", "npm run deploy")))).Allowed);
        });
    }
}
