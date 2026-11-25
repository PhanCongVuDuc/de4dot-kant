/*
    de4dot-side driver for the .NET Reactor "NecroBit native JIT-hook" variant
    (seen on builds where bodies are not cached in a managed Hashtable, so the
    older NecroBitMethodsRestorer gate misses and the static MethodsDecrypter
    throws "Could not initialize decrypter").

    This variant decrypts the real IL in a native compileMethod hook and
    *bulk-patches it straight into the in-memory PE image* when its loader runs.
    So recovery is dynamic but simple: load the assembly, run the loader, then
    read the patched image back with dnlib. On top of that it carries .NET
    Reactor control-flow obfuscation (opaque predicates keyed off an anti-tamper
    <Module>{guid} singleton whose int fields have fixed runtime values) and
    string encryption (a 'string M(int)' decrypter). We fold the anti-tamper
    fields to their live constants (so de4dot's own cflow pass can collapse the
    predicates) and inline every decrypted string, producing a module de4dot can
    finish with its normal rename/cflow passes.

    Everything here runs IN-PROCESS. The loader installs a process-wide JIT hook,
    but it only decrypts methods belonging to the target module (it checks scope),
    so de4dot itself is unaffected. No Revit/host assemblies are needed: only the
    loader, the anti-tamper cctors and the string decrypter run, none of which
    touch host types.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.IO;

namespace de4dot.code.deobfuscators.dotNET_Reactor.v5 {
	sealed class NecroBitNativeHookRestorer : IDisposable {
		// kept alive between DeobfuscateBegin (Prepare) and DeobfuscateEnd (BakeStringsLate)
		Assembly asm;
		MethodInfo rDec;
		uint strDecTok;
		ResolveEventHandler resolver;

		// --- static shape detection (no code runs) ---------------------------

		// The runtime type declares a static 'string M(int)' (string decrypter)
		// AND a method with the JIT compileMethod signature
		//   uint (IntPtr, IntPtr, <ByRef struct>, uint, IntPtr, ByRef uint).
		public static bool IsPresent(ModuleDefMD module) => FindRuntimeType(module) != null;

		static TypeDef FindRuntimeType(ModuleDefMD module) {
			foreach (var t in module.GetTypes()) {
				if (FindStringDecrypter(t) == null)
					continue;
				if (t.Methods.Any(IsCompileMethodSig))
					return t;
			}
			return null;
		}

		static bool IsCompileMethodSig(MethodDef m) {
			var s = m.MethodSig;
			if (s == null || s.RetType == null || s.RetType.FullName != "System.UInt32")
				return false;
			var p = s.Params;
			if (p.Count != 6)
				return false;
			return p[0].FullName == "System.IntPtr" && p[1].FullName == "System.IntPtr" &&
				p[2] is ByRefSig && p[3].FullName == "System.UInt32" &&
				p[4].FullName == "System.IntPtr" && p[5] is ByRefSig brs && brs.Next != null &&
				brs.Next.FullName == "System.UInt32";
		}

		static MethodDef FindStringDecrypter(TypeDef t) =>
			t.Methods.FirstOrDefault(m => m.IsStatic && m.MethodSig != null && m.MethodSig.RetType != null &&
				m.MethodSig.RetType.FullName == "System.String" && m.MethodSig.Params.Count == 1 &&
				m.MethodSig.Params[0].FullName == "System.Int32");

		// loader: static void() in the runtime type that installs the JIT hook
		// (references Marshal::GetFunctionPointerForDelegate), not the cctor.
		static MethodDef FindLoader(TypeDef t) =>
			t.Methods.FirstOrDefault(m => m.IsStatic && m.Name != ".cctor" && m.HasBody &&
				m.MethodSig != null && m.MethodSig.RetType.FullName == "System.Void" &&
				m.MethodSig.Params.Count == 0 &&
				m.Body.Instructions.Any(i => i.Operand is IMethod im &&
					im.Name == "GetFunctionPointerForDelegate"));

		// --- dynamic recovery -------------------------------------------------

		public struct Stats { public int bodies; public int folded; public int stringsBaked; public int stringCalls; public int distinctStrings; }

		// DeobfuscateBegin step: load the target, run its loader (which bulk-patches
		// the real IL into the in-memory PE image), rebuild every method body IN
		// PLACE on de4dot's own module from that image, and fold the anti-tamper
		// opaque-predicate constants so de4dot's cflow pass can collapse them.
		// Mutating the existing module (instead of returning bytes for de4dot to
		// reload) avoids a dnlib property-init NRE that the reload path hits during
		// later method removal. Strings are inlined later (BakeStringsLate), after
		// cflow has made each decrypter call's argument a single constant.
		public void Prepare(ModuleDefMD module, out Stats stats) {
			stats = new Stats();
			string path = module.Location;
			if (string.IsNullOrEmpty(path) || !File.Exists(path))
				throw new ApplicationException("module has no on-disk location to load dynamically");
			var baseDir = Path.GetDirectoryName(Path.GetFullPath(path));

			resolver = (s, e) => {
				try {
					var n = new AssemblyName(e.Name).Name + ".dll";
					var p = Path.Combine(baseDir, n);
					return File.Exists(p) ? Assembly.LoadFrom(p) : null;
				}
				catch { return null; }
			};
			AppDomain.CurrentDomain.AssemblyResolve += resolver;

			asm = Assembly.LoadFrom(path);

			// locate the runtime type by shape, then run cctor + loader
			var necro = FindRuntimeType(module);
			var strDec = FindStringDecrypter(necro);
			var loader = FindLoader(necro);
			var rNecro = asm.GetType(necro.FullName.Replace('/', '+'), false)
				?? asm.GetTypes().First(t => t.FullName == necro.FullName);
			RuntimeHelpers.RunClassConstructor(rNecro.TypeHandle);
			if (loader != null) {
				var rLoader = rNecro.GetMethods(AllFlags).FirstOrDefault(mi => mi.MetadataToken == (int)loader.MDToken.Raw);
				try { rLoader?.Invoke(null, null); } catch { }
			}
			rDec = rNecro.GetMethods(AllFlags).FirstOrDefault(mi => mi.MetadataToken == (int)strDec.MDToken.Raw);
			strDecTok = strDec.MDToken.Raw;

			IntPtr hmod = Marshal.GetHINSTANCE(asm.ManifestModule);
			if (hmod == (IntPtr)(-1) || hmod == IntPtr.Zero)
				throw new ApplicationException("could not get module HINSTANCE");

			// 0) rebuild real bodies in place (de4dot's module RVA == runtime RVA)
			stats.bodies = RebuildBodiesInPlace(module, hmod);

			// 1) fold anti-tamper opaque-predicate constants (read live)
			var (instVal, staticVal, singletonTokens) = ReadAntiTamper(asm);
			stats.folded = FoldAntiTamper(module, instVal, staticVal, singletonTokens);
			FoldIntConstants(module);
		}

		// DeobfuscateEnd step: now that de4dot's cflow pass has collapsed the (now
		// constant) opaque predicates, each string-decrypter call's argument is a
		// single ldc.i4; fold once more and inline every string via the runtime
		// decrypter (callable through reflection; the StackFrame anti-tamper does
		// not block reflected calls).
		public Stats BakeStringsLate(ModuleDefMD module) {
			var stats = new Stats();
			if (rDec == null) return stats;
			FoldIntConstants(module);
			BakeStrings(module, strDecTok, rDec, ref stats);
			return stats;
		}

		public void Dispose() {
			if (resolver != null) {
				AppDomain.CurrentDomain.AssemblyResolve -= resolver;
				resolver = null;
			}
		}

		// Read each method's real body from the patched memory image and rebuild it
		// against 'module' so operands resolve in-module. RVA is identical between
		// de4dot's file load and the runtime's memory image.
		static int RebuildBodiesInPlace(ModuleDefMD module, IntPtr hmod) {
			int n = 0;
			foreach (var t in module.GetTypes())
				foreach (var m in t.Methods) {
					if (m.RVA == 0 || !m.HasBody) continue;
					try {
						var bytes = ReadMethodBytes(hmod, (uint)m.RVA);
						if (bytes == null) continue;
						var reader = ByteArrayDataReaderFactory.CreateReader(bytes);
						var body = dnlib.DotNet.Emit.MethodBodyReader.CreateCilBody(module, reader, m.Parameters);
						if (body != null) { m.Body = body; n++; }
					}
					catch { }
				}
			return n;
		}

		// Read a full CLR method body (header + IL + EH) from memory, computing its
		// exact length from the method header.
		static byte[] ReadMethodBytes(IntPtr hmod, uint rva) {
			var one = new byte[1];
			Marshal.Copy(IntPtr.Add(hmod, (int)rva), one, 0, 1);
			int b0 = one[0];
			if ((b0 & 3) == 2) { // tiny
				int cs = b0 >> 2;
				var buf = new byte[1 + cs];
				Marshal.Copy(IntPtr.Add(hmod, (int)rva), buf, 0, buf.Length);
				return buf;
			}
			if ((b0 & 3) != 3)
				return null; // not a method header
			var hdr = new byte[12];
			Marshal.Copy(IntPtr.Add(hmod, (int)rva), hdr, 0, 12);
			int flags = hdr[0] | (hdr[1] << 8);
			int headerSize = ((flags >> 12) & 0xF) * 4;
			uint codeSize = BitConverter.ToUInt32(hdr, 4);
			long total = headerSize + codeSize;
			if ((flags & 0x8) != 0) { // MoreSects -> EH sections follow
				long pos = (total + 3) & ~3L;
				var sh = new byte[4];
				int kind;
				do {
					Marshal.Copy(IntPtr.Add(hmod, (int)(rva + pos)), sh, 0, 4);
					kind = sh[0];
					int dataSize = (kind & 0x40) != 0 ? (sh[1] | (sh[2] << 8) | (sh[3] << 16)) : sh[1];
					if (dataSize <= 0) break;
					pos += dataSize;
					pos = (pos + 3) & ~3L;
				} while ((kind & 0x80) != 0);
				total = pos;
			}
			if (total <= 0 || total > 0x400000)
				return null;
			var outb = new byte[total];
			Marshal.Copy(IntPtr.Add(hmod, (int)rva), outb, 0, (int)total);
			return outb;
		}

		const BindingFlags AllFlags = BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;

		// Read the live values of the <Module>{guid} anti-tamper int fields.
		static (Dictionary<uint,int> inst, Dictionary<uint,int> stat, HashSet<uint> singles) ReadAntiTamper(Assembly asm) {
			var inst = new Dictionary<uint,int>();
			var stat = new Dictionary<uint,int>();
			var singles = new HashSet<uint>();
			Type[] types;
			try { types = asm.GetTypes(); }
			catch (ReflectionTypeLoadException rex) { types = rex.Types.Where(t => t != null).ToArray(); }
			foreach (var at in types) {
				if (at == null || !at.Name.StartsWith("<Module>{"))
					continue;
				try { RuntimeHelpers.RunClassConstructor(at.TypeHandle); } catch { }
				foreach (var f in at.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)) {
					if (f.FieldType == typeof(int)) { try { stat[(uint)f.MetadataToken] = (int)f.GetValue(null); } catch { } }
				}
				var self = at.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
					.FirstOrDefault(f => f.FieldType == at);
				if (self == null) continue;
				singles.Add((uint)self.MetadataToken);
				object instObj; try { instObj = self.GetValue(null); } catch { continue; }
				if (instObj == null) continue;
				foreach (var f in at.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
					if (f.FieldType == typeof(int)) { try { inst[(uint)f.MetadataToken] = (int)f.GetValue(instObj); } catch { } }
				}
			}
			return (inst, stat, singles);
		}

		// Replace 'ldsfld staticInt' -> ldc, and 'ldsfld singleton; ldfld m_xxx' -> nop; ldc.
		static int FoldAntiTamper(ModuleDefMD mem, Dictionary<uint,int> inst, Dictionary<uint,int> stat, HashSet<uint> singles) {
			int folded = 0;
			foreach (var t in mem.GetTypes())
				foreach (var m in t.Methods) {
					if (m.Body == null) continue;
					var ins = m.Body.Instructions;
					for (int i = 0; i < ins.Count; i++) {
						var op = ins[i];
						if (op.OpCode.Code != Code.Ldsfld || !(op.Operand is IField sf))
							continue;
						uint tok = sf.MDToken.Raw;
						if (stat.TryGetValue(tok, out int sval)) {
							op.OpCode = OpCodes.Ldc_I4; op.Operand = sval; folded++; continue;
						}
						if (singles.Contains(tok) && i + 1 < ins.Count &&
							ins[i + 1].OpCode.Code == Code.Ldfld && ins[i + 1].Operand is IField inf &&
							inst.TryGetValue(inf.MDToken.Raw, out int ival)) {
							op.OpCode = OpCodes.Nop; op.Operand = null;
							ins[i + 1].OpCode = OpCodes.Ldc_I4; ins[i + 1].Operand = ival;
							folded++;
						}
					}
				}
			return folded;
		}

		// Collapse 'ldc.i4 a; (nop)*; ldc.i4 b; (nop)*; <int binop>' -> 'ldc.i4 (a op b)'.
		// Instructions are nop'd in place (offsets/branch targets stay valid); const
		// sub-expressions are never branch targets. Repeats until stable per method.
		static void FoldIntConstants(ModuleDefMD mem) {
			foreach (var t in mem.GetTypes())
				foreach (var m in t.Methods) {
					if (m.Body == null) continue;
					var ins = m.Body.Instructions;
					bool changed = true;
					while (changed) {
						changed = false;
						for (int i = 0; i < ins.Count; i++) {
							if (!TryGetLdcI4(ins[i], out int a)) continue;
							int j = i + 1; while (j < ins.Count && ins[j].OpCode.Code == Code.Nop) j++;
							if (j >= ins.Count || !TryGetLdcI4(ins[j], out int b)) continue;
							int k = j + 1; while (k < ins.Count && ins[k].OpCode.Code == Code.Nop) k++;
							if (k >= ins.Count || !TryBinOp(ins[k].OpCode.Code, a, b, out int r)) continue;
							ins[i].OpCode = OpCodes.Ldc_I4; ins[i].Operand = r;
							for (int z = i + 1; z <= k; z++) { ins[z].OpCode = OpCodes.Nop; ins[z].Operand = null; }
							changed = true;
						}
					}
				}
		}

		static bool TryBinOp(Code c, int a, int b, out int r) {
			r = 0;
			switch (c) {
				case Code.Xor: r = a ^ b; return true;
				case Code.And: r = a & b; return true;
				case Code.Or: r = a | b; return true;
				case Code.Add: r = unchecked(a + b); return true;
				case Code.Sub: r = unchecked(a - b); return true;
				case Code.Mul: r = unchecked(a * b); return true;
				default: return false;
			}
		}

		static void BakeStrings(ModuleDefMD mem, uint strDecTok, MethodInfo rDec, ref Stats stats) {
			var cache = new Dictionary<int,string>();
			foreach (var t in mem.GetTypes())
				foreach (var m in t.Methods) {
					if (m.Body == null) continue;
					var ins = m.Body.Instructions;
					for (int i = 0; i < ins.Count; i++) {
						var op = ins[i];
						if ((op.OpCode.Code != Code.Call && op.OpCode.Code != Code.Callvirt) || !(op.Operand is IMethod im))
							continue;
						if (im.MDToken.Raw != strDecTok)
							continue;
						stats.stringCalls++;
						int a = i - 1; while (a >= 0 && ins[a].OpCode.Code == Code.Nop) a--;
						if (a < 0 || !TryGetLdcI4(ins[a], out int id))
							continue;
						if (!cache.TryGetValue(id, out string str)) {
							try { str = rDec.Invoke(null, new object[] { id }) as string; } catch { str = null; }
							cache[id] = str;
						}
						if (str == null)
							continue;
						ins[a].OpCode = OpCodes.Ldstr; ins[a].Operand = str;
						op.OpCode = OpCodes.Nop; op.Operand = null;
						stats.stringsBaked++;
					}
				}
			stats.distinctStrings = cache.Count(kv => kv.Value != null);
		}

		static bool TryGetLdcI4(Instruction i, out int v) {
			v = 0; var c = i.OpCode.Code;
			if (c == Code.Ldc_I4) { v = (int)i.Operand; return true; }
			if (c == Code.Ldc_I4_S) { v = (sbyte)i.Operand; return true; }
			if (c >= Code.Ldc_I4_0 && c <= Code.Ldc_I4_8) { v = (int)c - (int)Code.Ldc_I4_0; return true; }
			if (c == Code.Ldc_I4_M1) { v = -1; return true; }
			return false;
		}
	}
}
