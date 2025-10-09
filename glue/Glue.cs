using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

app.MapGet("/", () => "PE Parser API is running! 🚀");

app.MapPost("/api/parse", async (HttpRequest request) =>
{
    var file = request.Form.Files["file"];
    if (file == null)
        return Results.BadRequest("No file provided");

    var tempFile = Path.GetTempFileName();
    await using (var stream = File.Create(tempFile))
        await file.CopyToAsync(stream);

    try
    {
        string output = RunParser(tempFile);
        return Results.Content(output, "application/json");
    }
    finally
    {
        File.Delete(tempFile);
    }
});

app.Run();

static string RunParser(string filePath)
{
    var exePath = Path.Combine(AppContext.BaseDirectory, "engine.exe");

    var psi = new ProcessStartInfo
    {
        FileName = exePath,
        Arguments = $"\"{filePath}\"",
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    using var proc = Process.Start(psi);
    string output = proc!.StandardOutput.ReadToEnd();
    string error = proc.StandardError.ReadToEnd();
    proc.WaitForExit();

    if (proc.ExitCode != 0)
        throw new Exception($"Parser failed: {error}");

    return output;
}
