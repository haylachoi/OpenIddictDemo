var builder = DistributedApplication.CreateBuilder(args);

var provider = builder.AddProject<Projects.OpenIddictDemo_Provider>("provider");

builder
    .AddProject<Projects.OpenIddictDemo_Device>("device")
    .WithReference(provider)
    .WaitFor(provider);

builder.Build().Run();
