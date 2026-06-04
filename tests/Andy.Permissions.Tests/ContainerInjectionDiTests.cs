using Andy.Permissions.DependencyInjection;
using Andy.Permissions.Model;
using Andy.Permissions.Prompt;
using Andy.Tools.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Andy.Permissions.Tests;

/// <summary>
/// End-to-end container tests through the real <c>AddAndyPermissions</c> DI wiring + environment-driven
/// injection bootstrap (RD9). Mutates process env, so all tests here run in one non-parallel collection
/// and restore env in a finally.
/// </summary>
[CollectionDefinition("env-mutating", DisableParallelization = true)]
public sealed class EnvMutatingCollection { }

[Collection("env-mutating")]
public sealed class ContainerInjectionDiTests
{
    private static async Task WithEnv(string? json, string? mode, Func<IToolExecutor, FakeInnerExecutor, RecordingPrompt?, Task> body, bool registerCountingPrompt)
    {
        var prevJson = Environment.GetEnvironmentVariable(PermissionInjectionBootstrap.JsonEnvVar);
        var prevMode = Environment.GetEnvironmentVariable(PermissionInjectionBootstrap.ModeEnvVar);
        var prevFile = Environment.GetEnvironmentVariable(PermissionInjectionBootstrap.FileEnvVar);
        try
        {
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.FileEnvVar, null);
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.JsonEnvVar, json);
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.ModeEnvVar, mode);

            var inner = new FakeInnerExecutor();
            RecordingPrompt? prompt = registerCountingPrompt ? new RecordingPrompt(PermissionDecision.DenyOnce) : null;

            var services = new ServiceCollection();
            services.AddSingleton<IToolExecutor>(inner);                 // the "real" executor we decorate
            if (prompt is not null)
            {
                services.AddSingleton<IPermissionPrompt>(prompt);        // count prompts; must be registered before AddAndyPermissions
            }

            services.AddAndyPermissions(o => o.UserFilePath = null);     // no user file; injection drives policy

            await using var sp = services.BuildServiceProvider();
            var executor = sp.GetRequiredService<IToolExecutor>();
            Assert.IsType<Andy.Permissions.Execution.PermissionedToolExecutor>(executor);

            await body(executor, inner, prompt);
        }
        finally
        {
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.JsonEnvVar, prevJson);
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.ModeEnvVar, prevMode);
            Environment.SetEnvironmentVariable(PermissionInjectionBootstrap.FileEnvVar, prevFile);
        }
    }

    private static Dictionary<string, object?> P(params (string, object?)[] kv) => kv.ToDictionary(x => x.Item1, x => x.Item2);

    [Fact]
    public async Task Injected_allows_run_with_zero_prompts()
    {
        var json = """{ "allow": ["read_file(*)", "write_file(*)", "execute_command(*)"] }""";
        await WithEnv(json, mode: null, registerCountingPrompt: true, body: async (exec, inner, prompt) =>
        {
            await exec.ExecuteAsync("read_file", P(("file_path", "/tmp/a")));
            await exec.ExecuteAsync("write_file", P(("file_path", "/tmp/b")));
            await exec.ExecuteAsync("execute_command", P(("command", "ls -la")));

            Assert.Equal(3, inner.ExecuteCount);
            Assert.Equal(0, prompt!.CallCount);   // the headline guarantee: inject first, never ask
        });
    }

    [Fact]
    public async Task Fail_closed_denies_uncovered_ask_without_a_tty()
    {
        // An injected Ask with no interactive prompt and default (fail-closed) mode ⇒ denied.
        var json = """{ "ask": ["execute_command(*)"] }""";
        await WithEnv(json, mode: null, registerCountingPrompt: false, body: async (exec, inner, _) =>
        {
            var result = await exec.ExecuteAsync("execute_command", P(("command", "npm run deploy")));
            Assert.False(result.IsSuccessful);
            Assert.Equal(0, inner.ExecuteCount);
        });
    }

    [Fact]
    public async Task Bypass_allows_ask_but_still_respects_deny()
    {
        var json = """{ "ask": ["execute_command(*)"], "deny": ["execute_command(npm run deploy:*)"] }""";
        await WithEnv(json, mode: "bypass", registerCountingPrompt: false, body: async (exec, inner, _) =>
        {
            var allowed = await exec.ExecuteAsync("execute_command", P(("command", "npm run test")));
            Assert.True(allowed.IsSuccessful);            // Ask ⇒ Allow under bypass

            var denied = await exec.ExecuteAsync("execute_command", P(("command", "npm run deploy")));
            Assert.False(denied.IsSuccessful);            // Deny is never collapsed by bypass
        });

        // inner ran exactly once (the allowed call)
    }
}
