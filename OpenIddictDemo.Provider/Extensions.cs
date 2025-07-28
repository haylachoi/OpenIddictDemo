using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;

namespace OpenIddictDemo.Provider;

public static class Extensions
{
    public static async Task<IHost> MigrateDbContextAsync<TContext>(
        this IHost host,
        Func<DatabaseFacade, CancellationToken?, Task>? postMigration = null,
        CancellationToken cancellationToken = default
    )
        where TContext : DbContext
    {
        using var scope = host.Services.CreateScope();
        var services = scope.ServiceProvider;
        var logger = services.GetRequiredService<ILogger<TContext>>();
        var context = services.GetService<TContext>();

        if (context is null)
            return host;

        try
        {
            await EnsureDatabaseCreatedAsync();
            await ApplyMigrationsAsync();
            await InvokePostMigrationAsync();
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "An error occurred while migrating the database used on context {DbContextName}",
                typeof(TContext).Name
            );
        }

        return host;

        async Task EnsureDatabaseCreatedAsync()
        {
            var dbCreator = context.GetService<IRelationalDatabaseCreator>();
            var strategy = context.Database.CreateExecutionStrategy();

            await strategy.ExecuteAsync(async () =>
            {
                if (!await dbCreator.ExistsAsync(cancellationToken))
                {
                    logger.LogInformation(
                        "Creating database associated with context {DbContextName}",
                        typeof(TContext).Name
                    );
                    await dbCreator.CreateAsync(cancellationToken);
                }
            });
        }

        async Task ApplyMigrationsAsync()
        {
            var strategy = context.Database.CreateExecutionStrategy();

            logger.LogInformation(
                "Migrating database associated with context {DbContextName}",
                typeof(TContext).Name
            );

            await strategy.ExecuteAsync(async () =>
            {
                await context.Database.MigrateAsync(cancellationToken);
            });

            logger.LogInformation(
                "Migrated database associated with context {DbContextName}",
                typeof(TContext).Name
            );
        }

        async Task InvokePostMigrationAsync()
        {
            if (postMigration is null)
                return;

            try
            {
                logger.LogInformation("Invoking postMigration function...");
                await postMigration.Invoke(context.Database, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error invoking postMigration");
            }
        }
    }
}
