using Andy.Permissions.Model;
using Andy.Permissions.Prompt;
using Andy.Permissions.Store;

namespace Andy.Permissions.DependencyInjection;

/// <summary>
/// Loads the highest-precedence injected permission layer for unattended/container runs (RD9), so that
/// pre-seeded Allow rules clear any Ask before a prompt is ever reached ("inject first, never ask").
/// Source precedence: <c>ANDY_PERMISSIONS_FILE</c> &gt; <c>ANDY_PERMISSIONS_JSON</c> &gt; baked image path.
/// </summary>
public static class PermissionInjectionBootstrap
{
    /// <summary>Environment variable naming a JSON file to load as the injected layer.</summary>
    public const string FileEnvVar = "ANDY_PERMISSIONS_FILE";

    /// <summary>Environment variable carrying inline JSON for the injected layer.</summary>
    public const string JsonEnvVar = "ANDY_PERMISSIONS_JSON";

    /// <summary>Environment variable selecting the non-interactive prompt mode.</summary>
    public const string ModeEnvVar = "ANDY_PERMISSION_MODE";

    /// <summary>Default baked-into-image path checked when no env source is set.</summary>
    public const string BakedPath = "/etc/andy/permissions.json";

    /// <summary>
    /// Resolves the injected rules from the environment, applying source precedence (RD9). A
    /// <paramref name="getEnv"/> override makes this unit-testable without touching process env.
    /// </summary>
    public static IReadOnlyList<PermissionRule> ResolveInjectedRules(
        Func<string, string?>? getEnv = null,
        Func<string, bool>? fileExists = null)
    {
        getEnv ??= Environment.GetEnvironmentVariable;
        fileExists ??= File.Exists;

        var filePath = getEnv(FileEnvVar);
        if (!string.IsNullOrWhiteSpace(filePath))
        {
            return RuleSetDocument.LoadFromFile(filePath, PermissionLayer.Injected);
        }

        var json = getEnv(JsonEnvVar);
        if (!string.IsNullOrWhiteSpace(json))
        {
            return RuleSetDocument.LoadFromJson(json, PermissionLayer.Injected);
        }

        if (fileExists(BakedPath))
        {
            return RuleSetDocument.LoadFromFile(BakedPath, PermissionLayer.Injected);
        }

        return Array.Empty<PermissionRule>();
    }

    /// <summary>Reads <c>ANDY_PERMISSION_MODE</c>, defaulting to fail-closed (RD9).</summary>
    public static PermissionMode ResolveMode(Func<string, string?>? getEnv = null)
    {
        getEnv ??= Environment.GetEnvironmentVariable;
        return NonInteractivePermissionPrompt.ParseMode(getEnv(ModeEnvVar));
    }

    /// <summary>Applies the resolved injected layer to a store.</summary>
    public static void Apply(IPermissionStore store, Func<string, string?>? getEnv = null, Func<string, bool>? fileExists = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        store.SetInjectedRules(ResolveInjectedRules(getEnv, fileExists));
    }
}
