using Andy.Permissions.Model;

namespace Andy.Permissions.Store;

/// <summary>
/// File-backed <see cref="IPermissionStore"/>. Loads builtin/user/project/local layers from disk at
/// construction, keeps session + injected layers in memory, and serves a cached merged view. Writes are
/// atomic (temp file + rename) and serialized by a lock so concurrent "allow always" appends can't lose
/// updates (§12.6 / RD4).
/// </summary>
public sealed class FilePermissionStore : IPermissionStore
{
    private readonly PermissionStoreOptions _options;
    private readonly object _lock = new();

    private List<PermissionRule> _fileAndBuiltin = [];   // builtin + user + project + local (from disk)
    private readonly List<PermissionRule> _session = [];
    private List<PermissionRule> _injected = [];
    private List<PermissionRule> _merged = [];

    public FilePermissionStore(PermissionStoreOptions? options = null)
    {
        _options = options ?? new PermissionStoreOptions();
        Reload();
    }

    /// <inheritdoc />
    public IReadOnlyList<PermissionRule> GetRules()
    {
        lock (_lock)
        {
            return _merged;
        }
    }

    /// <summary>Reloads the disk-backed layers and rebuilds the merged view.</summary>
    public void Reload()
    {
        lock (_lock)
        {
            var fileRules = new List<PermissionRule>(_options.Builtin);
            fileRules.AddRange(RuleSetDocument.LoadFromFile(_options.UserFilePath, PermissionLayer.User));
            fileRules.AddRange(RuleSetDocument.LoadFromFile(_options.ProjectFilePath, PermissionLayer.Project));
            fileRules.AddRange(RuleSetDocument.LoadFromFile(_options.LocalFilePath, PermissionLayer.Local));
            _fileAndBuiltin = fileRules;
            RebuildMerged();
        }
    }

    /// <inheritdoc />
    public Task AppendRuleAsync(string toolId, string specifier, PermissionOutcome outcome, PersistScope scope, CancellationToken cancellationToken = default)
    {
        if (scope == PersistScope.Once)
        {
            return Task.CompletedTask;
        }

        var ruleText = $"{toolId}({specifier})";

        if (scope == PersistScope.Session)
        {
            if (PermissionRule.TryParse(ruleText, outcome, PermissionLayer.Session, out var sessionRule) && sessionRule is not null)
            {
                AddSessionRule(sessionRule);
            }

            return Task.CompletedTask;
        }

        var (path, layer) = scope switch
        {
            PersistScope.User => (_options.UserFilePath, PermissionLayer.User),
            PersistScope.Project => (_options.ProjectFilePath, PermissionLayer.Project),
            PersistScope.Local => (_options.LocalFilePath, PermissionLayer.Local),
            _ => (null, PermissionLayer.User),
        };

        if (string.IsNullOrEmpty(path))
        {
            // No file configured for this scope; degrade to a session rule so the decision still sticks this run.
            if (PermissionRule.TryParse(ruleText, outcome, PermissionLayer.Session, out var fallback) && fallback is not null)
            {
                AddSessionRule(fallback);
            }

            return Task.CompletedTask;
        }

        lock (_lock)
        {
            var doc = RuleSetDocument.ReadForWrite(path!);
            doc.Add(ruleText, outcome);
            WriteAtomic(path!, doc.ToJson());
            Reload(); // picks up the new on-disk rule (and rebuilds merged)
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public void AddSessionRule(PermissionRule rule)
    {
        lock (_lock)
        {
            _session.Add(rule.Layer == PermissionLayer.Session ? rule : Retag(rule, PermissionLayer.Session));
            RebuildMerged();
        }
    }

    /// <inheritdoc />
    public void SetInjectedRules(IEnumerable<PermissionRule> rules)
    {
        lock (_lock)
        {
            _injected = rules.Select(r => r.Layer == PermissionLayer.Injected ? r : Retag(r, PermissionLayer.Injected)).ToList();
            RebuildMerged();
        }
    }

    private void RebuildMerged()
    {
        var merged = new List<PermissionRule>(_fileAndBuiltin.Count + _session.Count + _injected.Count);
        merged.AddRange(_fileAndBuiltin);
        merged.AddRange(_session);
        merged.AddRange(_injected);
        _merged = merged;
    }

    private static PermissionRule Retag(PermissionRule rule, PermissionLayer layer) => new()
    {
        Tool = rule.Tool,
        Specifier = rule.Specifier,
        Outcome = rule.Outcome,
        Layer = layer,
    };

    private static void WriteAtomic(string path, string contents)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(tmp, contents);
        File.Move(tmp, path, overwrite: true);
    }
}
