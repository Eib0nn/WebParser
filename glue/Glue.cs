using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRouting();
var app = builder.Build();

app.MapGet("/", () => "PE Parser API is running on Render");

app.MapPost("/api/parse", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var file = form.Files["file"];

    if (file == null)
        return Results.BadRequest("No file uploaded.");

    var tempFile = Path.GetTempFileName();
    await using (var stream = System.IO.File.Create(tempFile))
        await file.CopyToAsync(stream);

    try
    {
        var output = RunParser(tempFile);
        return Results.Content(output, "application/json");
    }
    finally
    {
        System.IO.File.Delete(tempFile);
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
