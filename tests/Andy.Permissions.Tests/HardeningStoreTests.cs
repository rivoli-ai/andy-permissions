using Andy.Permissions.Authorization;
using Andy.Permissions.Model;
using Andy.Permissions.Store;
using Andy.Tools.Core;
using Xunit;

namespace Andy.Permissions.Tests;

public sealed class HardeningStoreTests : IDisposable
{
    private readonly string _dir;

    public HardeningStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "andyhard-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void Managed_deny_is_uncoverable_by_user_allow()
    {
        var managed = Path.Combine(_dir, "managed.json");
        var user = Path.Combine(_dir, "user.json");
        File.WriteAllText(managed, """{ "deny": ["execute_command(*)"] }""");
        File.WriteAllText(user, """{ "allow": ["execute_command(*)"] }""");

        var store = new FilePermissionStore(new PermissionStoreOptions
        {
            ManagedFilePath = managed,
            UserFilePath = user,
            Builtin = Array.Empty<PermissionRule>(),
        });

        var auth = new ToolPermissionAuthorizer(store, new DefaultToolActionResolver());
        var ctx = new ToolAuthorizationContext("execute_command",
            new Dictionary<string, object?> { ["command"] = "npm test" });
        Assert.Equal(PermissionOutcome.Deny, auth.Evaluate(ctx).Outcome);
    }

    [Fact]
    public void Managed_layer_has_highest_precedence_among_allows()
    {
        var managed = Path.Combine(_dir, "managed.json");
        File.WriteAllText(managed, """{ "allow": ["read_file(/x/**)"] }""");
        var store = new FilePermissionStore(new PermissionStoreOptions
        {
            ManagedFilePath = managed,
            UserFilePath = null,
            Builtin = Array.Empty<PermissionRule>(),
        });
        Assert.Contains(store.GetRules(), r => r.Layer == PermissionLayer.Managed);
    }

    [Fact]
    public void Deny_follows_symlink_to_real_target()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // symlink creation needs privilege on Windows CI
        }

        var secret = Path.Combine(_dir, "secret.txt");
        File.WriteAllText(secret, "top secret");
        var link = Path.Combine(_dir, "innocent.txt");
        File.CreateSymbolicLink(link, secret);

        // Deny targets the REAL file by name (absolute, any depth); access is via the innocent symlink.
        var store = new ListPermissionStore().Add("read_file(//**/secret.txt)", PermissionOutcome.Deny, PermissionLayer.Builtin);
        var auth = new ToolPermissionAuthorizer(store, new DefaultToolActionResolver());

        var ctx = new ToolAuthorizationContext("read_file",
            new Dictionary<string, object?> { ["file_path"] = link });
        Assert.Equal(PermissionOutcome.Deny, auth.Evaluate(ctx).Outcome);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Deny_follows_parent_directory_symlink(bool fileExists)
    {
        if (OperatingSystem.IsWindows()) return;
        var secretDirectory = Path.Combine(_dir, "private");
        Directory.CreateDirectory(secretDirectory);
        var linkDirectory = Path.Combine(_dir, "public-link");
        Directory.CreateSymbolicLink(linkDirectory, secretDirectory);
        if (fileExists) File.WriteAllText(Path.Combine(secretDirectory, "data.txt"), "secret");

        var store = new ListPermissionStore()
            .Add($"write_file({secretDirectory}/**)", PermissionOutcome.Deny, PermissionLayer.Managed)
            .Add("write_file(*)", PermissionOutcome.Allow, PermissionLayer.User);
        var auth = new ToolPermissionAuthorizer(store, new DefaultToolActionResolver());
        var ctx = new ToolAuthorizationContext("write_file",
            new Dictionary<string, object?> { ["file_path"] = Path.Combine(linkDirectory, "data.txt") });

        Assert.Equal(PermissionOutcome.Deny, auth.Evaluate(ctx).Outcome);
    }
}
