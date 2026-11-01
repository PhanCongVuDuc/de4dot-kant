using System.ComponentModel;
using System.Reflection;
using de4dot.code;
using de4dot.code.AssemblyClient;
using de4dot.code.deobfuscators;
using dnlib.DotNet;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace de4dot.mcp {

	/// <summary>
	/// This tool help deobfuscate
	/// </summary>
	[McpServerToolType]
	public sealed class ObfuscatorTool {
		[McpServerTool(Name = "detectObfuscator"), Description("Detect obfuscator from specified DLL file")]
		public static async Task<AIContent> DetectObfuscator(
			McpServer mcpServer,
			DeobfuscationSessionManager manager,
			[Description("The file to detect obfuscator obfuscate")] string obfuscatedFile,
			CancellationToken cancellationToken) {
			try {
				//mcpServer.ElicitAsync<ObfuscatedFileResource>(cancellationToken).Wait(cancellationToken);
				var session = manager.GetSession(mcpServer.SessionId!);
				var moduleContext = new ModuleContext(session.AssemblyResolver);
				var assemblyClientFactory = new NewAppDomainAssemblyClientFactory();
				var options = new ObfuscatedFile.Options() {
					ControlFlowDeobfuscation = false,
					KeepObfuscatorTypes = true,
					Filename = obfuscatedFile,
					StringDecrypterType = DecrypterType.None,
					NewFilename = Path.ChangeExtension(obfuscatedFile, ".deobfuscate.dll"),
				};
				var file = new ObfuscatedFile(options, moduleContext, assemblyClientFactory);
				file.DeobfuscatorContext = session.DeobfuscatorContext;
				file.Load(CreateDeobfuscators());
				var deob = file.Deobfuscator;
				session.File = file;
				await mcpServer.SendNotificationAsync("notifications/resources/list_changed");
				return new TextContent(deob.TypeLong);
			}
			catch (Exception ex) {
				return new ErrorContent(ex.Message);
			}
		}

		[McpServerTool(Name = "deobfuscate"), Description(
			"Deobfuscate a .NET assembly the same way the de4dot CLI does (deobfuscate -> rename -> save) and write the result to disk. " +
			"Returns the detected obfuscator and the output path.")]
		public static async Task<AIContent> Deobfuscate(
			McpServer mcpServer,
			DeobfuscationSessionManager manager,
			[Description("Input assembly. Omit to reuse the file from the last detectObfuscator call.")] string? obfuscatedFile = null,
			[Description("Output path. Default: '<name>-cleaned.dll' next to the input.")] string? outputFile = null,
			[Description("Rename obfuscated symbols (CLI default). Use false for WPF/XAML assemblies (= --dont-rename).")] bool rename = true,
			[Description("Keep obfuscator types/fields/methods (= --keep-types).")] bool keepTypes = false,
			[Description("Deobfuscate control flow (CLI default true).")] bool controlFlow = true,
			[Description("Force an obfuscator by type/name, e.g. 'co' or 'Crypto Obfuscator'. Omit to auto-detect.")] string? method = null,
			CancellationToken cancellationToken = default) {
			try {
				var session = manager.GetSession(mcpServer.SessionId);
				string input = obfuscatedFile ?? session.File?.Filename
					?? throw new ArgumentException("Chưa có file: truyền obfuscatedFile hoặc gọi detectObfuscator trước.");
				input = Path.GetFullPath(input);
				string output = Path.GetFullPath(outputFile ?? Path.Combine(
					Path.GetDirectoryName(input)!, Path.GetFileNameWithoutExtension(input) + "-cleaned" + Path.GetExtension(input)));

				// Tuỳ chọn như CLI (detectObfuscator chỉ dò nhanh: tắt control-flow, không giải chuỗi -> không dùng lại).
				var options = new ObfuscatedFile.Options {
					Filename = input,
					NewFilename = output,
					ControlFlowDeobfuscation = controlFlow,
					KeepObfuscatorTypes = keepTypes,
					StringDecrypterType = DecrypterType.Default,
					RenamerFlags = DefaultRenamerFlags,
				};
				var file = new ObfuscatedFile(options, new ModuleContext(session.AssemblyResolver), new NewAppDomainAssemblyClientFactory());
				file.DeobfuscatorContext = session.DeobfuscatorContext;
				file.Load(method == null ? CreateDeobfuscators() : CreateDeobfuscator(method));

				file.DeobfuscateBegin();
				file.Deobfuscate();
				file.DeobfuscateEnd();
				if (rename)
					new de4dot.code.renamer.Renamer(session.DeobfuscatorContext, new List<IObfuscatedFile> { file }, DefaultRenamerFlags).Rename();
				file.Save();

				session.File = file;
				await mcpServer.SendNotificationAsync("notifications/resources/list_changed");
				return new TextContent($"{file.Deobfuscator.TypeLong} -> {output}");
			} catch (Exception ex) {
				return new ErrorContent(ex.Message);
			}
		}

		// Giống mặc định của de4dot.cui FilesDeobfuscator.Options.
		static readonly de4dot.code.renamer.RenamerFlags DefaultRenamerFlags =
			de4dot.code.renamer.RenamerFlags.RenameNamespaces |
			de4dot.code.renamer.RenamerFlags.RenameTypes |
			de4dot.code.renamer.RenamerFlags.RenameProperties |
			de4dot.code.renamer.RenamerFlags.RenameEvents |
			de4dot.code.renamer.RenamerFlags.RenameFields |
			de4dot.code.renamer.RenamerFlags.RenameMethods |
			de4dot.code.renamer.RenamerFlags.RenameMethodArgs |
			de4dot.code.renamer.RenamerFlags.RenameGenericParams |
			de4dot.code.renamer.RenamerFlags.RestorePropertiesFromNames |
			de4dot.code.renamer.RenamerFlags.RestoreEventsFromNames |
			de4dot.code.renamer.RenamerFlags.RestoreProperties |
			de4dot.code.renamer.RenamerFlags.RestoreEvents;

		[McpServerTool(Name = "saveDeobfuscated"), Description("Return deobfuscated file")]
		public static CallToolResult SaveDeobfuscated(
			McpServer mcpServer,
			DeobfuscationSessionManager manager,
			CancellationToken cancellationToken) {
			try {
				var session = manager.GetSession(mcpServer.SessionId!);
				var file = session.File;
				var fileName = Path.GetFileName(file.NewFilename);
				// Thành công -> IsError = false (bản gốc để true khiến client coi là lỗi).
				return new CallToolResult() { IsError = false, Content = [new ResourceLinkBlock() { Name = fileName, Uri = $"de4dot://files/{fileName}" }] };
			}
			catch (Exception ex) {
				return new CallToolResult() { IsError = true, Content = [new TextContentBlock() { Text = ex.Message }] };
			}
		}

		static IList<IDeobfuscator> CreateDeobfuscators() {
			return [.. CreateDeobfuscatorInfos().Select(_ => _.CreateDeobfuscator())];
		}

		static IList<IDeobfuscator> CreateDeobfuscator(string? longName) {
			return [.. CreateDeobfuscatorInfos().Select(_ => _.CreateDeobfuscator()).Where(_ => _.TypeLong == longName || _.Name == longName || _.Type == longName || longName == null)];
		}

		static IList<IDeobfuscatorInfo> CreateDeobfuscatorInfos() {
			var local = new List<IDeobfuscatorInfo> {
				new de4dot.code.deobfuscators.Unknown.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Agile_NET.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Babel_NET.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.CodeFort.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.CodeVeil.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.CodeWall.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Confuser.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.CryptoObfuscator.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.DeepSea.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Dotfuscator.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.dotNET_Reactor.v3.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.dotNET_Reactor.v4.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Eazfuscator_NET.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Goliath_NET.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.ILProtector.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.MaxtoCode.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.MPRESS.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Obfuscar.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Rummage.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Skater_NET.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.SmartAssembly.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Spices_Net.DeobfuscatorInfo(),
				new de4dot.code.deobfuscators.Xenocode.DeobfuscatorInfo(),
			};
			return local;
		}

		static IList<IDeobfuscatorInfo> LoadPlugin(string assembly) {
			var plugins = new List<IDeobfuscatorInfo>();
			try {
				foreach (var item in Assembly.LoadFile(assembly).GetTypes()) {
					var interfaces = new List<Type>(item.GetInterfaces());
					if (item.IsClass && interfaces.Contains(typeof(IDeobfuscatorInfo)))
						plugins.Add((IDeobfuscatorInfo)Activator.CreateInstance(item));
				}
			}
			catch {
			}
			return plugins;
		}
	}
}
