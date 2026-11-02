/*
    Copyright (C) 2026 de4dot-kant contributors

    This file is part of de4dot.

    de4dot is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
*/

using de4dot.code.renamer;
using dnlib.DotNet;

namespace de4dot.code.deobfuscators.CryptoObfuscator {
	/// <summary>
	/// Biến thể CO mới (DiRoots ProSheets 2.4.2, 2026) đổi tên method implement interface của state machine
	/// (vd <c>MoveNext</c> -> <c>\u0017</c>) và nối lại bằng <c>.override</c> tường minh. ILSpy tìm state machine
	/// async/iterator theo đúng tên "MoveNext" -> không thấy là ra state machine thô (không compile lại được).
	/// Đổi lại về tên compiler C# đặt: MoveNext / SetStateMachine giữ tên trần, các explicit impl khác
	/// (Reset, Dispose, get_Current, GetEnumerator...) đặt "<Interface>.<Method>" như csc.
	/// Chỉ đụng type compiler-generated, nên chạy được cả khi --keep-names m (WPF).
	/// </summary>
	class StateMachineMethodRestorer {
		readonly ModuleDef module;

		public StateMachineMethodRestorer(ModuleDef module) => this.module = module;

		public int Restore() {
			int n = 0;
			var renamer = new DefRenamer(module);
			foreach (var type in module.GetTypes()) {
				if (!IsStateMachine(type))
					continue;
				foreach (var method in type.Methods) {
					if (method.Overrides.Count != 1)
						continue;
					var decl = method.Overrides[0].MethodDeclaration;
					var iface = decl?.DeclaringType;
					if (iface == null)
						continue;
					var newName = CsName(iface, decl.Name.String);
					if (newName == null || method.Name == newName)
						continue;
					Logger.v("State machine method: {0} => {1}", Utils.RemoveNewlines(method.FullName), newName);
					renamer.Rename(method, newName);
					n++;
				}
				// Property của explicit impl (IEnumerator<T>.Current...) đặt tên theo getter: "<Interface>.Current".
				foreach (var prop in type.Properties) {
					var getter = prop.GetMethod;
					if (getter == null || getter.Overrides.Count != 1)
						continue;
					var g = getter.Name.String;
					int dot = g.LastIndexOf(".get_");
					if (dot < 0)
						continue;
					var newName = g.Substring(0, dot) + "." + g.Substring(dot + 5);
					if (prop.Name != newName) {
						renamer.Rename(prop, newName);
						n++;
					}
				}
			}
			if (n != 0)
				Logger.v("Restored {0} state machine method names", n);
			return n;
		}

		static string CsName(ITypeDefOrRef iface, string methodName) {
			var ns = iface.Namespace ?? "";
			var name = iface.Name ?? "";
			if (ns == "System.Runtime.CompilerServices" && name == "IAsyncStateMachine")
				return methodName;              // MoveNext, SetStateMachine
			if (ns == "System.Collections" && name == "IEnumerator" && methodName == "MoveNext")
				return "MoveNext";
			if (ns == "System.Collections" || ns == "System.Collections.Generic" || ns == "System" ||
				ns == "System.Threading.Tasks.Sources") {
				// csc: "System.Collections.Generic.IEnumerator<T>.get_Current" -> metadata dùng tên không có <T>.
				var full = iface is TypeSpec ts ? ts.TypeSig.ToTypeDefOrRef()?.FullName ?? iface.FullName : iface.FullName;
				int tick = full.IndexOf('`');
				if (tick >= 0)
					full = full.Substring(0, tick);
				return full + "." + methodName;
			}
			return null;
		}

		static bool IsStateMachine(TypeDef type) {
			bool cg = type.Name.String.StartsWith("<");
			foreach (var ca in type.CustomAttributes) {
				if (ca.TypeFullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute")
					cg = true;
			}
			foreach (var i in type.Interfaces) {
				var n = i.Interface?.FullName;
				if (n == "System.Runtime.CompilerServices.IAsyncStateMachine")
					return true;
				if (cg && (n == "System.Collections.IEnumerator" || n == "System.Collections.IEnumerable"))
					return true;
			}
			return false;
		}
	}
}
