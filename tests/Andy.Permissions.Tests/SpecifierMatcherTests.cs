using Andy.Permissions.Matching;
using Andy.Permissions.Model;
using Xunit;

namespace Andy.Permissions.Tests;

public class SpecifierMatcherTests
{
    [Theory]
    [InlineData("/etc/**", "/etc/passwd", true)]
    [InlineData("/etc/**", "/etc", true)]                 // trailing /** matches the dir itself
    [InlineData("/etc/**", "/etc/./passwd", true)]        // C2: normalize-before-match
    [InlineData("/etc/**", "/etc//passwd", true)]
    [InlineData("/etc/**", "/etc/../tmp/x", false)]       // escapes the protected dir
    [InlineData("/var/*", "/var/log", true)]
    [InlineData("/var/*", "/var/log/syslog", false)]      // single * does not cross separators
    [InlineData("*", "/anything/at/all", true)]
    public void MatchPath_globs_and_normalizes(string spec, string value, bool expected)
    {
        Assert.Equal(expected, SpecifierMatcher.MatchPath(spec, value, workingDirectory: null));
    }

    [Fact]
    public void MatchPath_is_case_insensitive_like_SecurityManager()
    {
        // Documents macOS/Windows behavior (OrdinalIgnoreCase).
        Assert.True(SpecifierMatcher.MatchPath("/Etc/**", "/etc/passwd", null));
    }

    [Fact]
    public void MatchPath_expands_tilde_on_both_sides()
    {
        Assert.True(SpecifierMatcher.MatchPath("~/.ssh/**", "~/.ssh/id_rsa", null));
    }

    [Fact]
    public void MatchPath_resolves_relative_specifier_against_working_directory()
    {
        Assert.True(SpecifierMatcher.MatchPath("./secrets/**", "secrets/key", "/work"));
        Assert.False(SpecifierMatcher.MatchPath("./secrets/**", "other/key", "/work"));
    }

    [Theory]
    [InlineData("git status:*", "git status", true)]
    [InlineData("git status:*", "git status --short", true)]
    [InlineData("git status:*", "git statusx", false)]    // argument boundary
    [InlineData("git:*", "git push", true)]
    [InlineData("*", "anything here", true)]
    [InlineData("npm run test", "npm run test", true)]
    [InlineData("npm run test", "npm run build", false)]
    public void MatchCommand_prefix_and_boundary(string spec, string cmd, bool expected)
    {
        Assert.Equal(expected, SpecifierMatcher.MatchCommand(spec, cmd));
    }

    [Theory]
    [InlineData("domain:example.com", "example.com", true)]
    [InlineData("*.example.com", "api.example.com", true)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData("example.com", "other.com", false)]
    public void MatchHost_exact_and_wildcard(string spec, string host, bool expected)
    {
        Assert.Equal(expected, SpecifierMatcher.MatchHost(spec, host));
    }

    [Fact]
    public void MatchesTool_handles_wildcard_and_exact()
    {
        Assert.True(SpecifierMatcher.MatchesTool("*", "read_file"));
        Assert.True(SpecifierMatcher.MatchesTool("read_file", "read_file"));
        Assert.False(SpecifierMatcher.MatchesTool("read_file", "write_file"));
    }

    [Fact]
    public void MatchesResource_none_only_matches_star()
    {
        var none = new ResourceAccess(ResourceKind.None, "");
        Assert.True(SpecifierMatcher.MatchesResource("*", none, null));
        Assert.False(SpecifierMatcher.MatchesResource("read_file", none, null));
    }
}
