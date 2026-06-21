using System.Collections.Generic;
using Andy.Permissions.Authorization;
using Andy.Permissions.Model;
using Xunit;

namespace Andy.Permissions.Tests;

/// <summary>
/// Single-file tools (delete_file, read_file, write_file, file_editor) must resolve the target path
/// under any of the common parameter aliases, not just "file_path". Otherwise the gate degrades to a
/// "None" resource and the permission prompt shows no file name (e.g. "delete_file: None ''").
/// </summary>
public class DefaultToolActionResolverTests
{
    [Theory]
    [InlineData("file_path")]
    [InlineData("path")]
    [InlineData("filepath")]
    [InlineData("filename")]
    [InlineData("file")]
    public void DeleteFile_ResolvesPath_UnderCommonAliases(string parameterName)
    {
        var resolver = new DefaultToolActionResolver();

        var resources = resolver.Resolve("delete_file",
            new Dictionary<string, object?> { [parameterName] = "/tmp/target.txt" });

        Assert.Single(resources);
        Assert.Equal(ResourceKind.Path, resources[0].Kind);
        Assert.Equal("/tmp/target.txt", resources[0].Value);
    }

    [Fact]
    public void SamePathUnderMultipleAliases_DeDuplicatesToOneResource()
    {
        var resolver = new DefaultToolActionResolver();

        var resources = resolver.Resolve("delete_file",
            new Dictionary<string, object?> { ["file_path"] = "/tmp/x", ["path"] = "/tmp/x" });

        Assert.Single(resources);
    }

    [Fact]
    public void NoPathParameter_YieldsNoResource()
    {
        var resolver = new DefaultToolActionResolver();

        var resources = resolver.Resolve("delete_file",
            new Dictionary<string, object?> { ["unrelated"] = "value" });

        Assert.Empty(resources);
    }
}
