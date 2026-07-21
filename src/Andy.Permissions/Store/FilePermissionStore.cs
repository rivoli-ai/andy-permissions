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

    // A read-only snapshot rebuilt (never mutated in place) on every change, so GetRules can hand it out
    // directly: it is O(1), thread-safe, and callers cannot cast it back to a List and mutate policy (#9).
    private IReadOnlyList<PermissionRule> _merged = Array.Empty<PermissionRule>();

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
            // _merged is a ReadOnlyCollection wrapping a list this store never mutates again, so returning
            // it directly is safe: it is an immutable snapshot the caller cannot use to alter store state.
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
            fileRules.AddRange(RuleSetDocument.LoadFromFile(_options.ManagedFilePath, PermissionLayer.Managed));
            _fileAndBuiltin = fileRules;
            RebuildMerged();
        }
    }

    /// <inheritdoc />
    public Task AppendRuleAsync(string toolId, string specifier, PermissionOutcome outcome, PersistScope scope, CancellationToken cancellationToken = default)
    {
        // Enforce the documented tool-id grammar (snake_case or "*") up front so a malformed id can never
        // be written to disk as a dead rule (#8). This is a programmer error, so it throws synchronously.
        if (!PermissionRule.IsValidToolId(toolId))
        {
            throw new ArgumentException(
                $"Invalid tool id '{toolId}'; expected snake_case (e.g. 'read_file') or '*'.", nameof(toolId));
        }

        // Cancellation is observed before any work begins; a canceled request never appends a rule (#8).
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled(cancellationToken);
        }

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
            // Re-check under the lock: if the request was canceled while queued behind another writer, bail
            // before touching disk. Once the atomic write starts it runs to completion so the temp+rename
            // invariant is never left half-applied (#8).
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled(cancellationToken);
            }

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
        _merged = merged.AsReadOnly(); // hand out an immutable snapshot (#9)
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
