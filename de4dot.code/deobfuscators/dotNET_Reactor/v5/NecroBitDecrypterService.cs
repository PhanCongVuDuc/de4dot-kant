/*
    NecroBit bulk-decrypt generic service. Runs in the AssemblyData service
    (in-process on net8/net10 via SameAppDomainAssemblyServerLoader). It loads the
    obfuscated assembly, runs the module cctor so NecroBit decrypts every body into
    its static Hashtable, then reads that table and returns the real IL + EH per
    method. It also exposes the runtime string decrypter for de4dot's string inliner.

    Detection is by shape, not by name: the single type that declares both a static
    System.Collections.Hashtable field and a static 'string M(int32)' method is the
    NecroBit decrypter type. The Hashtable maps (imageBase + rva + headerSize) to a
    struct { int ilSize; IntPtr ilPtr; IntPtr stubBodyPtr }. ilPtr -> decrypted IL;
    stubBodyPtr -> the original fake stub body, whose trailing 4-byte-aligned region
    holds the real EH section.
*/

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using dnlib.DotNet;
using AssemblyData;

namespace de4dot.code.deobfuscators.dotNET_Reactor.v5 {
	sealed class NecroBitDecrypterService : IUserGenericService {
		public const int MSG_DUMP_METHODS = 0;		// -> NecroBitDumpResult
		public const int MSG_DECRYPT_STRING = 1;	// args[0]=int offset -> string
		public const int MSG_EVAL_FIELD_CHAIN = 2;	// args[0]=int[] tokens (static,instance...) -> boxed value or null

		Assembly reflAsm;
		MethodInfo stringMethod;

		[CreateUserGenericService]
		public static IUserGenericService Create() => new NecroBitDecrypterService();

		public void Dispose() { }

		public void AssemblyLoaded(Assembly assembly) {
			reflAsm = assembly;
			try { RuntimeHelpers.RunModuleConstructor(reflAsm.ManifestModule.ModuleHandle); } catch { }
		}

		public object HandleMessage(int msg, object[] args) {
			switch (msg) {
			case MSG_DUMP_METHODS:
				return Dump();
			case MSG_DECRYPT_STRING:
				return DecryptString((int)args[0]);
			case MSG_EVAL_FIELD_CHAIN:
				return EvalFieldChain((int[])args[0]);
			default:
				throw new ApplicationException($"Invalid msg: {msg:X8}");
			}
		}

		string DecryptString(int offset) {
			if (stringMethod == null)
				return null;
			try { return (string)stringMethod.Invoke(null, new object[] { offset }); }
			catch { return null; }
		}

		// Reads a static field, then walks instance fields, returning the final boxed
		// value. The Reactor string offset is 'const ^ (staticKeyHolder.perStringKey)';
		// these key fields are runtime-initialized, so they must be read live.
		object EvalFieldChain(int[] tokens) {
			if (tokens == null || tokens.Length == 0)
				return null;
			try {
				var m = reflAsm.ManifestModule;
				object cur = m.ResolveField(tokens[0]).GetValue(null);
				for (int i = 1; i < tokens.Length; i++) {
					if (cur == null)
						return null;
					cur = m.ResolveField(tokens[i]).GetValue(cur);
				}
				return cur;
			}
			catch { return null; }
		}

		NecroBitDumpResult Dump() {
			var result = new NecroBitDumpResult();

			// Static-shape detection on a throwaway dnlib view of the same image.
			ModuleDefMD mod;
			try { mod = ModuleDefMD.Load(reflAsm.ManifestModule); }
			catch { return result; }

			TypeDef decType = null; FieldDef htField = null; MethodDef strMethod = null;
			foreach (var t in mod.GetTypes()) {
				var hf = t.Fields.FirstOrDefault(f => f.IsStatic && f.FieldType != null &&
					f.FieldType.FullName == "System.Collections.Hashtable");
				if (hf == null)
					continue;
				var sm = t.Methods.FirstOrDefault(m => m.IsStatic && m.MethodSig != null &&
					m.MethodSig.RetType != null && m.MethodSig.RetType.FullName == "System.String" &&
					m.MethodSig.Params.Count == 1 && m.MethodSig.Params[0].FullName == "System.Int32");
				if (sm == null)
					continue;
				decType = t; htField = hf; strMethod = sm;
				break;
			}
			if (decType == null)
				return result;

			result.decrypterTypeName = decType.FullName;

			// Resolve the same members via reflection and force the cctor to run.
			Type rtType;
			try { rtType = reflAsm.ManifestModule.ResolveType(decType.MDToken.ToInt32()); }
			catch { return result; }
			try { RuntimeHelpers.RunClassConstructor(rtType.TypeHandle); } catch { }

			var rtField = rtType.GetField(htField.Name, BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
			if (rtField == null || !(rtField.GetValue(null) is IDictionary ht) || ht.Count == 0)
				return result;

			stringMethod = rtType.GetMethod(strMethod.Name,
				BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic,
				null, new[] { typeof(int) }, null);
			if (stringMethod != null)
				result.stringDecrypterToken = (int)strMethod.MDToken.ToUInt32();

			// Value struct layout: one int (ilSize) + two IntPtr (ilPtr, stubPtr).
			var ve = ht.Cast<DictionaryEntry>().First().Value;
			var vt = ve.GetType();
			var fInt = vt.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
				.First(f => f.FieldType == typeof(int));
			var fPtrs = vt.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
				.Where(f => f.FieldType == typeof(IntPtr)).ToArray();
			if (fPtrs.Length < 1)
				return result;

			var map = new Dictionary<long, object>(ht.Count);
			foreach (DictionaryEntry e in ht)
				map[Convert.ToInt64(e.Key)] = e.Value;

			long imageBase = Marshal.GetHINSTANCE(reflAsm.ManifestModule).ToInt64();

			foreach (var type in mod.GetTypes()) {
				foreach (var m in type.Methods) {
					if ((uint)m.RVA == 0)
						continue;
					long a = imageBase + (uint)m.RVA;
					byte hb;
					try { hb = Marshal.ReadByte(new IntPtr(a)); } catch { continue; }
					bool tiny = (hb & 0x3) == 0x2;
					long ilAddr = a + (tiny ? 1 : 12);
					if (!map.TryGetValue(ilAddr, out var v))
						continue;

					int size = (int)fInt.GetValue(v);
					if (size <= 0 || size > 0x400000)
						continue;
					long ilPtr = ((IntPtr)fPtrs[0].GetValue(v)).ToInt64();
					long stubPtr = fPtrs.Length > 1 ? ((IntPtr)fPtrs[1].GetValue(v)).ToInt64() : 0;

					byte[] il = new byte[size];
					try { Marshal.Copy(new IntPtr(ilPtr), il, 0, size); } catch { continue; }

					ushort maxStack = 8;
					uint localTok = 0;
					bool initLocals = false;
					if (!tiny) {
						ushort stubFlags = (ushort)Marshal.ReadInt16(new IntPtr(a));
						maxStack = (ushort)Marshal.ReadInt16(new IntPtr(a + 2));
						localTok = (uint)Marshal.ReadInt32(new IntPtr(a + 8));
						initLocals = (stubFlags & 0x10) != 0;
					}

					byte[] eh = stubPtr != 0 ? LocateEh(stubPtr, size) : null;

					result.methods.Add(new NecroBitMethodInfo {
						rid = m.Rid,
						il = il,
						eh = eh,
						localVarSigTok = localTok,
						maxStack = maxStack,
						initLocals = initLocals,
					});
					result.decryptedCount++;
					if (eh != null)
						result.ehCount++;
				}
			}

			result.found = result.decryptedCount > 0;
			return result;
		}

		// The real EH section sits 4-byte-aligned in the original stub body region.
		// Scan the first few aligned offsets for a well-formed small/fat EH section
		// whose clause offsets all fall within the IL.
		static byte[] LocateEh(long stubPtr, int ilSize) {
			byte[] buf;
			try { buf = new byte[192]; Marshal.Copy(new IntPtr(stubPtr), buf, 0, buf.Length); }
			catch { return null; }

			for (int o = 0; o + 4 < buf.Length && o < 48; o += 4) {
				byte kind = buf[o];
				if (kind != 0x01 && kind != 0x41)
					continue;
				int dataSize = kind == 0x01 ? buf[o + 1] : (buf[o + 1] | (buf[o + 2] << 8) | (buf[o + 3] << 16));
				if (dataSize < 8)
					continue;
				int clauseSize = kind == 0x01 ? 12 : 24;
				if ((dataSize - 4) % clauseSize != 0)
					continue;
				int nClauses = (dataSize - 4) / clauseSize;
				if (nClauses < 1 || nClauses > 50)
					continue;

				int co = o + 4;
				int tryOff, tryLen, hOff, hLen;
				if (kind == 0x01) {
					tryOff = buf[co + 2] | (buf[co + 3] << 8);
					tryLen = buf[co + 4];
					hOff = buf[co + 5] | (buf[co + 6] << 8);
					hLen = buf[co + 7];
				}
				else {
					tryOff = BitConverter.ToInt32(buf, co + 4);
					tryLen = BitConverter.ToInt32(buf, co + 8);
					hOff = BitConverter.ToInt32(buf, co + 12);
					hLen = BitConverter.ToInt32(buf, co + 16);
				}
				if (tryOff < 0 || tryLen <= 0 || tryOff + tryLen > ilSize || hOff + hLen > ilSize || hOff < tryOff)
					continue;

				byte[] eh;
				if (o + dataSize <= buf.Length) {
					eh = new byte[dataSize];
					Array.Copy(buf, o, eh, 0, dataSize);
				}
				else {
					eh = new byte[dataSize];
					try { Marshal.Copy(new IntPtr(stubPtr + o), eh, 0, dataSize); } catch { return null; }
				}
				return eh;
			}
			return null;
		}
	}
}
