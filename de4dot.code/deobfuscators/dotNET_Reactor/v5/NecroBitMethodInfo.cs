/*
    .NET Reactor NecroBit (JIT-hook / bulk-decrypt) dynamic support for de4dot v5.

    NecroBit (newer variant) does NOT patch IL in-place and is not statically
    decryptable (it swaps the ILCode pointer in CORINFO_METHOD_INFO at JIT time).
    Instead it decrypts every method body in bulk, at module-cctor time, into a
    static Hashtable. We run the module cctor in a child service, read that table,
    and rebuild each dnlib method body (IL + exception handlers).

    These are the serializable data carriers passed between the de4dot process
    and the AssemblyData generic service.
*/

using System;
using System.Collections.Generic;

namespace de4dot.code.deobfuscators.dotNET_Reactor.v5 {
	// One recovered method body. 'eh' is the raw CLR extra-sections blob
	// (small 0x01 / fat 0x41 EH section) or null when the method has no EH.
	[Serializable]
	sealed class NecroBitMethodInfo {
		public uint rid;
		public byte[] il;
		public byte[] eh;
		public uint localVarSigTok;
		public ushort maxStack;
		public bool initLocals;
	}

	// Result of the bulk dump. Matched back to the de4dot module by method rid.
	[Serializable]
	sealed class NecroBitDumpResult {
		public bool found;
		public string decrypterTypeName;
		public int decryptedCount;
		public int ehCount;
		public int stringDecrypterToken;	// 0x06xxxxxx, or 0 if none
		public List<NecroBitMethodInfo> methods = new List<NecroBitMethodInfo>();
	}
}
