using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRouting();

var app = builder.Build();

app.MapGet("/", () => "PE Parser API is running on Render! 🚀");

app.MapPost("/api/parse", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var file = form.Files["file"];

    if (file == null)
        return Results.BadRequest(new { error = "No file uploaded" });

    var tempFile = Path.GetTempFileName();
    
    try
    {
        await using (var stream = System.IO.File.Create(tempFile))
            await file.CopyToAsync(stream);

        var json = ParserGlue.RunParser(tempFile);
        return Results.Content(json, "application/json");
    }
    catch (Exception ex)
    {
        return Results.Problem(
            detail: ex.Message,
            statusCode: 500,
            title: "Parser Error"
        );
    }
    finally
    {
        if (System.IO.File.Exists(tempFile))
            System.IO.File.Delete(tempFile);
    }
});

app.Run();