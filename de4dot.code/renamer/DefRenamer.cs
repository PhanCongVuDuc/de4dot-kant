/*
    Copyright (C) 2026 de4dot-kant contributors

    This file is part of de4dot.

    de4dot is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
*/

using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.renamer {
	/// <summary>
	/// Đổi tên field/method def ngoài Renamer chính mà KHÔNG làm gãy tham chiếu.
	/// Tham chiếu tới def thường là token def (tự theo), nhưng member của type GENERIC được gọi qua
	/// MemberRef trên TypeSpec (<c>Foo`1&lt;!T&gt;::Bar</c>) — MemberRef giữ tên dạng chuỗi, đổi tên def mà không
	/// đổi MemberRef là gãy (decompiler ra <c>this._0020()</c> trỏ vào hư không).
	/// Phải tạo DefRenamer TRƯỚC khi đổi tên bất cứ gì: nó resolve MemberRef -> def theo tên hiện tại.
	/// </summary>
	public class DefRenamer {
		readonly Dictionary<IMemberDef, List<MemberRef>> refs = new Dictionary<IMemberDef, List<MemberRef>>();

		public DefRenamer(ModuleDef module) {
			var seen = new HashSet<MemberRef>();
			foreach (var type in module.GetTypes()) {
				foreach (var method in type.Methods) {
					if (method.Body != null) {
						foreach (var instr in method.Body.Instructions)
							Add(module, instr.Operand, seen);
					}
					foreach (var o in method.Overrides) {
						Add(module, o.MethodBody, seen);
						Add(module, o.MethodDeclaration, seen);
					}
				}
			}
		}

		void Add(ModuleDef module, object operand, HashSet<MemberRef> seen) {
			if (operand is MethodSpec ms)
				operand = ms.Method;
			if (!(operand is MemberRef mr) || !seen.Add(mr))
				return;
			var declType = mr.DeclaringType?.ResolveTypeDef();
			if (declType == null || declType.Module != module)
				return;
			IMemberDef def = mr.IsMethodRef ? (IMemberDef)mr.ResolveMethod() : mr.ResolveField();
			if (def == null)
				return;
			if (!refs.TryGetValue(def, out var list))
				refs[def] = list = new List<MemberRef>();
			list.Add(mr);
		}

		public void Rename(IMemberDef def, string newName) {
			switch (def) {
			case MethodDef m: m.Name = newName; break;
			case FieldDef f: f.Name = newName; break;
			case PropertyDef p: p.Name = newName; break;
			case EventDef e: e.Name = newName; break;
			case TypeDef t: t.Name = newName; break;
			}
			if (refs.TryGetValue(def, out var list)) {
				foreach (var mr in list)
					mr.Name = newName;
			}
		}
	}
}
