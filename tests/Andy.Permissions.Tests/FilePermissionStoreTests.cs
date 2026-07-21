using Andy.Permissions.Model;
using Andy.Permissions.Store;
using Xunit;

namespace Andy.Permissions.Tests;

public sealed class FilePermissionStoreTests : IDisposable
{
    private readonly string _dir;

    public FilePermissionStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "andyperm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private PermissionStoreOptions Options() => new()
    {
        UserFilePath = Path.Combine(_dir, "user.json"),
        ProjectFilePath = Path.Combine(_dir, "project.json"),
        LocalFilePath = Path.Combine(_dir, "local.json"),
        ManagedFilePath = Path.Combine(_dir, "managed.json"), // keep hermetic (don't read the system default)
        Builtin = Array.Empty<PermissionRule>(),
    };

    [Fact]
    public void Loads_rules_from_files_with_correct_layers()
    {
        File.WriteAllText(Path.Combine(_dir, "user.json"), """{ "allow": ["read_file(/u/**)"] }""");
        File.WriteAllText(Path.Combine(_dir, "project.json"), """{ "deny": ["read_file(/p/**)"] }""");

        var store = new FilePermissionStore(Options());
        var rules = store.GetRules();

        Assert.Contains(rules, r => r.Tool == "read_file" && r.Layer == PermissionLayer.User && r.Outcome == PermissionOutcome.Allow);
        Assert.Contains(rules, r => r.Tool == "read_file" && r.Layer == PermissionLayer.Project && r.Outcome == PermissionOutcome.Deny);
    }

    [Fact]
    public async Task Append_persists_and_survives_reconstruction()
    {
        var store = new FilePermissionStore(Options());
        await store.AppendRuleAsync("write_file", "/tmp/x", PermissionOutcome.Allow, PersistScope.User);

        Assert.Contains(store.GetRules(), r => r.Tool == "write_file" && r.Specifier == "/tmp/x");

        var reopened = new FilePermissionStore(Options());
        Assert.Contains(reopened.GetRules(), r => r.Tool == "write_file" && r.Specifier == "/tmp/x" && r.Outcome == PermissionOutcome.Allow);
    }

    [Fact]
    public void Corrupt_file_is_ignored_not_thrown()
    {
        File.WriteAllText(Path.Combine(_dir, "user.json"), "{ this is not valid json ");
        var ex = Record.Exception(() => new FilePermissionStore(Options()).GetRules());
        Assert.Null(ex);
    }

    [Fact]
    public void Empty_and_missing_files_yield_no_rules()
    {
        File.WriteAllText(Path.Combine(_dir, "user.json"), "   ");
        var store = new FilePermissionStore(Options());
        Assert.Empty(store.GetRules());
    }

    [Fact]
    public async Task Concurrent_appends_do_not_lose_updates()
    {
        var store = new FilePermissionStore(Options());
        var tasks = Enumerable.Range(0, 20)
            .Select(i => store.AppendRuleAsync("read_file", $"/p{i}", PermissionOutcome.Allow, PersistScope.User))
            .ToArray();
        await Task.WhenAll(tasks);

        var reopened = new FilePermissionStore(Options());
        for (var i = 0; i < 20; i++)
        {
            Assert.Contains(reopened.GetRules(), r => r.Specifier == $"/p{i}");
        }
    }

    [Fact]
    public void Injected_rules_replace_previous_injection()
    {
        var store = new FilePermissionStore(Options());
        store.SetInjectedRules([PermissionRule.Parse("read_file(/a)", PermissionOutcome.Allow, PermissionLayer.Injected)]);
        store.SetInjectedRules([PermissionRule.Parse("read_file(/b)", PermissionOutcome.Allow, PermissionLayer.Injected)]);

        var injected = store.GetRules().Where(r => r.Layer == PermissionLayer.Injected).ToList();
        Assert.Single(injected);
        Assert.Equal("/b", injected[0].Specifier);
    }
}
