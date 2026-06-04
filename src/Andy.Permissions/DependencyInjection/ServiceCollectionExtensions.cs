using Andy.Permissions.Authorization;
using Andy.Permissions.Execution;
using Andy.Permissions.Prompt;
using Andy.Permissions.Store;
using Andy.Tools.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Andy.Permissions.DependencyInjection;

/// <summary>
/// DI wiring for the permission system. Call <see cref="AddAndyPermissions"/> <em>after</em>
/// <c>AddAndyTools(...)</c> so it can decorate the registered <see cref="IToolExecutor"/> (RD6).
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the authorizer, store, action resolver, and a default non-interactive prompt, then
    /// decorates the existing <see cref="IToolExecutor"/> with <see cref="PermissionedToolExecutor"/>.
    /// Hosts that want an interactive prompt register their own <see cref="IPermissionPrompt"/> before
    /// this call (the prompt is registered with <c>TryAddSingleton</c>, so register yours first).
    /// </summary>
    public static IServiceCollection AddAndyPermissions(
        this IServiceCollection services,
        Action<PermissionStoreOptions>? configureStore = null,
        bool applyInjectionFromEnvironment = true)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new PermissionStoreOptions();
        configureStore?.Invoke(options);
        services.TryAddSingleton(options);

        services.TryAddSingleton<IToolActionResolver, DefaultToolActionResolver>();
        services.TryAddSingleton<IPermissionStore>(sp =>
        {
            var store = new FilePermissionStore(sp.GetRequiredService<PermissionStoreOptions>());
            if (applyInjectionFromEnvironment)
            {
                PermissionInjectionBootstrap.Apply(store);
            }

            return store;
        });
        services.TryAddSingleton<IToolPermissionAuthorizer, ToolPermissionAuthorizer>();

        // Default consent provider: non-interactive, fail-closed unless ANDY_PERMISSION_MODE=bypass.
        services.TryAddSingleton<IPermissionPrompt>(_ =>
            new NonInteractivePermissionPrompt(PermissionInjectionBootstrap.ResolveMode()));

        DecorateToolExecutor(services);
        return services;
    }

    /// <summary>
    /// Replaces the registered <see cref="IToolExecutor"/> with a <see cref="PermissionedToolExecutor"/>
    /// wrapping the original. No-op if no <see cref="IToolExecutor"/> is registered yet (call after
    /// <c>AddAndyTools</c>).
    /// </summary>
    public static void DecorateToolExecutor(IServiceCollection services)
    {
        var existing = services.LastOrDefault(d => d.ServiceType == typeof(IToolExecutor));
        if (existing is null)
        {
            return;
        }

        services.Remove(existing);
        var buildInner = BuildInnerFactory(existing, services);

        services.AddSingleton<IToolExecutor>(sp => new PermissionedToolExecutor(
            buildInner(sp),
            sp.GetRequiredService<IToolPermissionAuthorizer>(),
            sp.GetRequiredService<IPermissionPrompt>(),
            sp.GetRequiredService<IPermissionStore>(),
            sp.GetService<IToolRegistry>()));
    }

    private static Func<IServiceProvider, IToolExecutor> BuildInnerFactory(ServiceDescriptor existing, IServiceCollection services)
    {
        if (existing.ImplementationInstance is IToolExecutor instance)
        {
            return _ => instance;
        }

        if (existing.ImplementationFactory is not null)
        {
            return sp => (IToolExecutor)existing.ImplementationFactory(sp);
        }

        var implType = existing.ImplementationType
            ?? throw new InvalidOperationException("Existing IToolExecutor registration has no implementation to decorate.");

        // Register the concrete implementation under its own type so it can be resolved as the inner.
        services.TryAddSingleton(implType);
        return sp => (IToolExecutor)sp.GetRequiredService(implType);
    }
}
