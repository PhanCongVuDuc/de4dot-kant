/*
    de4dot-side driver for NecroBit bulk-decrypt. Decides (statically, without
    executing anything) whether the module is the NecroBit JIT-hook variant, then
    spins up the AssemblyData generic service to recover the real method bodies and
    rewrites them in-place, exception handlers included. The service connection is
    kept open so the string inliner can call the runtime string decrypter.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.IO;
using AssemblyData;
using de4dot.code.AssemblyClient;

namespace de4dot.code.deobfuscators.dotNET_Reactor.v5 {
	sealed class NecroBitMethodsRestorer : IDisposable {
		readonly ModuleDefMD module;
		IAssemblyClient client;

		public int RestoredCount { get; private set; }
		public int EhCount { get; private set; }
		public int EhFailed { get; private set; }
		public int StringsDecrypted { get; private set; }
		public int StringsUnresolved { get; private set; }
		public string DecrypterTypeName { get; private set; }
		public MethodDef StringDecrypterMethod { get; private set; }

		readonly Dictionary<long, long?> fieldChainCache = new Dictionary<long, long?>();

		public NecroBitMethodsRestorer(ModuleDefMD module) => this.module = module;

		// Static shape gate: exactly the NecroBit decrypter type declares both a
		// static System.Collections.Hashtable field and a static 'string M(int)'.
		// No code runs here; if this returns false we never load the assembly.
		public static bool IsPresent(ModuleDefMD module) {
			foreach (var t in module.GetTypes()) {
				bool hasHt = t.Fields.Any(f => f.IsStatic && f.FieldType != null &&
					f.FieldType.FullName == "System.Collections.Hashtable");
				if (!hasHt)
					continue;
				bool hasStr = t.Methods.Any(m => m.IsStatic && m.MethodSig != null &&
					m.MethodSig.RetType != null && m.MethodSig.RetType.FullName == "System.String" &&
					m.MethodSig.Params.Count == 1 && m.MethodSig.Params[0].FullName == "System.Int32");
				if (hasStr)
					return true;
			}
			return false;
		}

		public bool Restore() {
			if (!IsPresent(module))
				return false;

			NecroBitDumpResult dump;
			var serverVersion = NewProcessAssemblyClientFactory.GetServerClrVersion(module);
			client = new NewProcessAssemblyClientFactory(serverVersion).Create(AssemblyServiceType.Generic);
			client.Connect();
			client.WaitConnected();
			client.GenericService.LoadUserService(typeof(NecroBitDecrypterService), null);
			client.GenericService.LoadAssembly(module.Location);
			dump = client.GenericService.SendMessage(NecroBitDecrypterService.MSG_DUMP_METHODS, new object[0]) as NecroBitDumpResult;

			if (dump == null || !dump.found) {
				DisposeClient();
				return false;
			}

			DecrypterTypeName = dump.decrypterTypeName;
			if (dump.stringDecrypterToken != 0)
				StringDecrypterMethod = module.ResolveToken(dump.stringDecrypterToken) as MethodDef;

			var byRid = new Dictionary<uint, NecroBitMethodInfo>(dump.methods.Count);
			foreach (var info in dump.methods)
				byRid[info.rid] = info;

			foreach (var type in module.GetTypes()) {
				foreach (var method in type.Methods) {
					if (method.Body == null)
						continue;
					if (!byRid.TryGetValue(method.Rid, out var info))
						continue;
					if (RebuildBody(method, info))
						RestoredCount++;
				}
			}
			return RestoredCount > 0;
		}

		bool RebuildBody(MethodDef method, NecroBitMethodInfo info) {
			// First try with EH; if dnlib rejects the EH section, fall back to IL only
			// (same result the pointer-only dump would give, never worse).
			if (info.eh != null) {
				var body = TryBuild(method, info, info.eh);
				if (body != null && body.HasExceptionHandlers) {
					method.Body = body;
					method.Body.InitLocals = info.initLocals;
					EhCount++;
					return true;
				}
				EhFailed++;
			}
			var plain = TryBuild(method, info, null);
			if (plain == null)
				return false;
			method.Body = plain;
			method.Body.InitLocals = info.initLocals;
			return true;
		}

		CilBody TryBuild(MethodDef method, NecroBitMethodInfo info, byte[] eh) {
			try {
				using var ms = new MemoryStream();
				int flags = 0x3 | (eh != null ? 0x8 : 0) | (info.initLocals ? 0x10 : 0);
				int w = flags | (3 << 12);	// fat header, 3 dwords
				ms.WriteByte((byte)(w & 0xff));
				ms.WriteByte((byte)(w >> 8));
				ms.WriteByte((byte)(info.maxStack & 0xff));
				ms.WriteByte((byte)(info.maxStack >> 8));
				var cs = BitConverter.GetBytes((uint)info.il.Length);
				ms.Write(cs, 0, 4);
				var lt = BitConverter.GetBytes(info.localVarSigTok);
				ms.Write(lt, 0, 4);
				ms.Write(info.il, 0, info.il.Length);
				if (eh != null) {
					while ((ms.Length & 3) != 0)
						ms.WriteByte(0);
					ms.Write(eh, 0, eh.Length);
				}
				var reader = ByteArrayDataReaderFactory.CreateReader(ms.ToArray());
				return MethodBodyReader.CreateCilBody(module, reader, method.Parameters);
			}
			catch {
				return null;
			}
		}

		public string DecryptString(int offset) {
			if (client == null)
				return null;
			return client.GenericService.SendMessage(NecroBitDecrypterService.MSG_DECRYPT_STRING, new object[] { offset }) as string;
		}

		long? EvalFieldChain(int[] tokens) {
			long key = 17;
			foreach (var t in tokens)
				key = key * 1000000007L + (uint)t;
			if (fieldChainCache.TryGetValue(key, out var cached))
				return cached;
			long? val = null;
			var r = client?.GenericService.SendMessage(NecroBitDecrypterService.MSG_EVAL_FIELD_CHAIN, new object[] { tokens });
			if (r != null) {
				try { val = Convert.ToInt64(r); } catch { }
			}
			fieldChainCache[key] = val;
			return val;
		}

		// The string decrypter takes an int offset computed from a self-contained
		// constant expression xored with a runtime key field read
		// (staticKeyHolder.perStringKey). de4dot's static inliner cannot read the live
		// key fields, so emulate the arg expression here (live field reads via the
		// service) and replace the whole sequence with a literal ldstr.
		public void DecryptStrings() {
			if (StringDecrypterMethod == null || client == null)
				return;
			foreach (var type in module.GetTypes()) {
				foreach (var method in type.Methods) {
					if (method.Body == null)
						continue;
					var instrs = method.Body.Instructions;
					for (int i = 0; i < instrs.Count; i++) {
						if (instrs[i].OpCode.Code != Code.Call || instrs[i].Operand != StringDecrypterMethod)
							continue;

						int start = FindArgStart(instrs, i);
						long? offset = start < 0 ? null : EvalArg(instrs, start, i);
						string str = offset == null ? null : DecryptString((int)offset.Value);
						if (str == null) {
							if (StringsUnresolved < 5) {
								string ctx = "";
								for (int j = System.Math.Max(0, i - 6); j <= i; j++)
									ctx += instrs[j].OpCode.Code + " ";
								Logger.v("NecroBit str unresolved: {0}", ctx);
							}
							StringsUnresolved++;
							continue;
						}
						for (int j = start; j < i; j++) {
							instrs[j].OpCode = OpCodes.Nop;
							instrs[j].Operand = null;
						}
						instrs[i].OpCode = OpCodes.Ldstr;
						instrs[i].Operand = str;
						StringsDecrypted++;
					}
				}
			}
		}

		// Walk back from the call to the first instruction of the single-value arg
		// expression, using stack usage. Returns -1 if it can't be isolated.
		static int FindArgStart(IList<Instruction> instrs, int callIndex) {
			int needed = 1;
			int j = callIndex - 1;
			for (; j >= 0 && needed > 0; j--) {
				instrs[j].CalculateStackUsage(out int pushes, out int pops);
				needed += pops - pushes;
			}
			return needed == 0 ? j + 1 : -1;
		}

		abstract class V { }
		sealed class Known : V { public long Value; public Known(long v) => Value = v; }
		sealed class Chain : V { public List<int> Tokens; public Chain(List<int> t) => Tokens = t; }
		sealed class Unknown : V { public static readonly Unknown I = new Unknown(); }

		long? EvalArg(IList<Instruction> instrs, int start, int callIndex) {
			var st = new Stack<V>();
			for (int k = start; k < callIndex; k++) {
				var ins = instrs[k];
				var c = ins.OpCode.Code;
				if (ins.IsLdcI4()) { st.Push(new Known(ins.GetLdcI4Value())); continue; }
				switch (c) {
				case Code.Ldc_I8: st.Push(new Known((long)ins.Operand)); break;
				case Code.Not: st.Push(Un(st) is long a1 ? (V)new Known(~a1) : Unknown.I); break;
				case Code.Neg: st.Push(Un(st) is long a2 ? (V)new Known(-a2) : Unknown.I); break;
				case Code.Conv_I4: case Code.Conv_U4: st.Push(Un(st) is long a3 ? (V)new Known((int)a3) : Unknown.I); break;
				case Code.Conv_I8: case Code.Conv_U8: case Code.Conv_I: case Code.Conv_U: break;	// keep top
				case Code.Xor: st.Push(Bin(st, (a, b) => a ^ b)); break;
				case Code.And: st.Push(Bin(st, (a, b) => a & b)); break;
				case Code.Or: st.Push(Bin(st, (a, b) => a | b)); break;
				case Code.Add: st.Push(Bin(st, (a, b) => a + b)); break;
				case Code.Sub: st.Push(Bin(st, (a, b) => a - b)); break;
				case Code.Mul: st.Push(Bin(st, (a, b) => a * b)); break;
				case Code.Shl: st.Push(Bin(st, (a, b) => a << (int)b)); break;
				case Code.Shr: case Code.Shr_Un: st.Push(Bin(st, (a, b) => a >> (int)b)); break;
				case Code.Ldsfld: {
					var f = ins.Operand as IField;
					if (f == null) { st.Push(Unknown.I); break; }
					if (IsInt(f)) {
						var v = EvalFieldChain(new[] { f.MDToken.ToInt32() });
						st.Push(v != null ? (V)new Known(v.Value) : Unknown.I);
					}
					else
						st.Push(new Chain(new List<int> { f.MDToken.ToInt32() }));
					break;
				}
				case Code.Ldfld: {
					var baseV = st.Count > 0 ? st.Pop() : Unknown.I;
					var f = ins.Operand as IField;
					if (baseV is Chain ch && f != null) {
						var toks = new List<int>(ch.Tokens) { f.MDToken.ToInt32() };
						if (IsInt(f)) {
							var v = EvalFieldChain(toks.ToArray());
							st.Push(v != null ? (V)new Known(v.Value) : Unknown.I);
						}
						else
							st.Push(new Chain(toks));
					}
					else
						st.Push(Unknown.I);
					break;
				}
				case Code.Dup: st.Push(st.Count > 0 ? st.Peek() : Unknown.I); break;
				case Code.Pop: if (st.Count > 0) st.Pop(); break;
				case Code.Nop: break;
				default: return null;	// unhandled opcode in arg expression
				}
			}
			return st.Count > 0 && st.Peek() is Known top ? (int)top.Value : (long?)null;
		}

		static bool IsInt(IField f) {
			var et = f.FieldSig?.Type?.ElementType;
			return et == dnlib.DotNet.ElementType.I4 || et == dnlib.DotNet.ElementType.U4 ||
				et == dnlib.DotNet.ElementType.I || et == dnlib.DotNet.ElementType.U;
		}

		static object Un(Stack<V> st) => st.Count > 0 && st.Pop() is Known k ? (object)k.Value : null;

		static V Bin(Stack<V> st, Func<long, long, long> op) {
			var b = st.Count > 0 ? st.Pop() : Unknown.I;
			var a = st.Count > 0 ? st.Pop() : Unknown.I;
			return a is Known ka && b is Known kb ? (V)new Known(op(ka.Value, kb.Value)) : Unknown.I;
		}

		void DisposeClient() {
			if (client != null) {
				try { client.Dispose(); } catch { }
				client = null;
			}
		}

		public void Dispose() => DisposeClient();
	}
}
