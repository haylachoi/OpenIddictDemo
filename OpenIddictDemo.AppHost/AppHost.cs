var builder = DistributedApplication.CreateBuilder(args);

// Add the OpenIddict Provider service
var provider = builder.AddProject<Projects.OpenIddictDemo_Provider>("provider");

var apiService = builder
    .AddProject<Projects.OpenIddictDemo_ApiService>("apiservice")
    .WithHttpHealthCheck("/health")
    .WithReference(provider)
    .WaitFor(provider);

builder
    .AddProject<Projects.OpenIddictDemo_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(apiService)
    .WithReference(provider)
    .WaitFor(apiService)
    .WaitFor(provider);

builder.Build().Run();
