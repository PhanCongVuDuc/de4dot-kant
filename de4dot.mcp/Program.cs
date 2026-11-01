using System.ComponentModel;
using System.Text;
using de4dot.mcp;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

// --stdio: chạy như MCP server cục bộ (client tự khởi động tiến trình, giao tiếp qua stdin/stdout).
// Mặc định (không cờ): HTTP như bản gốc.
if (args.Contains("--stdio")) {
	// stdout là kênh giao thức MCP; log của lõi de4dot (in qua Console) phải sang stderr.
	Console.SetOut(Console.Error);
	var hostBuilder = Host.CreateApplicationBuilder(args.Where(a => a != "--stdio").ToArray());
	hostBuilder.Logging.ClearProviders();
	hostBuilder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
	hostBuilder.Services.AddMcpServer()
		.WithStdioServerTransport()
		.WithTools<ObfuscatorTool>()
		.WithResources<ObfuscatedFileResource>();
	hostBuilder.Services.AddSingleton<DeobfuscationSessionManager>();
	await hostBuilder.Build().RunAsync();
	return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddMcpServer()
	.WithHttpTransport()
	.WithTools<ObfuscatorTool>()
	.WithResources<ObfuscatedFileResource>();
builder.Services.AddSingleton<DeobfuscationSessionManager>();

var app = builder.Build();
app.UseHttpsRedirection();
app.MapMcp();

await app.RunAsync();

[McpServerResourceType]
class ObfuscatedFileResource {

	[McpServerResource(UriTemplate = "de4dot://files/{id}", Name = "Obfuscated file")]
	//[Description("The obfuscated file")]
	public static ReadResourceResult TemplateResource(RequestContext<ReadResourceRequestParams> requestContext, string id) {
		if (requestContext.Services is null) {
			throw new NotSupportedException($"Unknown resource: {requestContext.Params?.Uri}");
		}

		var manager = requestContext.Services.GetRequiredService<DeobfuscationSessionManager>();
		var sessionId = requestContext.Server.SessionId!;
		var session = manager.GetSession(sessionId);
		if (session.File is null) {
			throw new NotSupportedException($"Unknown resource: {requestContext.Params?.Uri}");
		}

		var file = session.File;
		var memoryStream = new MemoryStream();
		file.Save(memoryStream);
		memoryStream.Position = 0;

		return new() {
			Contents = [new BlobResourceContents {
				Blob = Encoding.UTF8.GetBytes(Convert.ToBase64String(memoryStream.ToArray())).AsMemory(),
				MimeType = "application/octet-stream",
				Uri = $"de4dot://files/{id}",
			}]
		};
	}
}
