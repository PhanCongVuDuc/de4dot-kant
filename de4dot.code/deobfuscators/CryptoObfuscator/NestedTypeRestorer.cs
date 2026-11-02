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

namespace de4dot.code.deobfuscators.CryptoObfuscator {
	/// <summary>
	/// Biến thể CO mới (DiRoots ProSheets 2.4.2, 2026) kéo type compiler-generated ra khỏi class sở hữu:
	/// struct state machine async/iterator và closure (display class, <c>&lt;&gt;c</c>) bị dồn vào
	/// holder top-level trong namespace "A". Decompiler (ILSpy) chỉ dựng lại async/await, yield và lambda
	/// khi các type đó là NESTED trong chính class chứa method -> output thành state machine thô,
	/// không compile lại được (CS1673, CS0122, CS0165...).
	/// Ở đây gắn lại:
	///  1. State machine S của method M ([AsyncStateMachine]/[IteratorStateMachine]/[AsyncIteratorStateMachine](typeof(S)))
	///     -> nested trong M.DeclaringType.
	///  2. Type compiler-generated C còn lại: mọi method bên ngoài C dùng tới C quy về cùng một class chủ O
	///     (leo qua các type compiler-generated đã nested) -> nested C trong O.
	/// Tham chiếu trong module là token nên không cần sửa IL; chỉ đổi DeclaringType + cờ visibility.
	/// </summary>
	class NestedTypeRestorer {
		readonly ModuleDef module;
		int moved;

		public NestedTypeRestorer(ModuleDef module) => this.module = module;

		public int Restore() {
			RestoreStateMachines();
			// Closure lồng closure: chủ của closure trong chỉ biết được sau khi closure ngoài đã về chỗ.
			for (int pass = 0; pass < 8; pass++) {
				if (!RestoreClosures())
					break;
			}
			if (moved != 0)
				Logger.v("Re-nested {0} compiler-generated types", moved);
			return moved;
		}

		static readonly string[] stateMachineAttrs = {
			"System.Runtime.CompilerServices.AsyncStateMachineAttribute",
			"System.Runtime.CompilerServices.IteratorStateMachineAttribute",
			"System.Runtime.CompilerServices.AsyncIteratorStateMachineAttribute",
		};

		void RestoreStateMachines() {
			foreach (var type in new List<TypeDef>(module.GetTypes())) {
				foreach (var method in type.Methods) {
					foreach (var ca in method.CustomAttributes) {
						if (System.Array.IndexOf(stateMachineAttrs, ca.TypeFullName) < 0)
							continue;
						if (ca.ConstructorArguments.Count != 1)
							continue;
						var sm = (ca.ConstructorArguments[0].Value as TypeSig)?.ToTypeDefOrRef()?.ResolveTypeDef();
						if (sm == null || sm.Module != module)
							continue;
						if (sm.DeclaringType == type)
							continue;
						if (IsAncestor(sm, type))
							continue;
						Move(sm, type);
					}
				}
			}
		}

		bool RestoreClosures() {
			// owners[C] = tập class chủ (đã quy về type không compiler-generated) của mọi method ngoài C dùng C.
			var owners = new Dictionary<TypeDef, HashSet<TypeDef>>();
			var unknown = new HashSet<TypeDef>();
			foreach (var type in module.GetTypes()) {
				foreach (var method in type.Methods) {
					if (method.Body == null)
						continue;
					foreach (var instr in method.Body.Instructions) {
						var target = GetReferencedType(instr.Operand);
						if (target == null || target.Module != module || !IsCompilerGenerated(target))
							continue;
						// Bản thân C (hoặc type lồng trong C) dùng C thì không nói lên chủ.
						if (target == type || IsAncestor(type, target))
							continue;
						var owner = OwnerOf(type);
						if (owner == null) {
							unknown.Add(target);
							continue;
						}
						if (!owners.TryGetValue(target, out var set))
							owners[target] = set = new HashSet<TypeDef>();
						set.Add(owner);
					}
				}
			}

			bool any = false;
			foreach (var kv in owners) {
				var c = kv.Key;
				if (kv.Value.Count != 1 || unknown.Contains(c))
					continue;
				var o = First(kv.Value);
				if (o == c || IsAncestor(c, o) || IsAncestor(o, c))
					continue;   // đã nằm trong chủ (hoặc chủ nằm trong c)
				// Chỉ chuyển type đang "lạc chỗ": top-level, hoặc lồng trong holder compiler-generated.
				if (c.DeclaringType != null && !IsCompilerGenerated(c.DeclaringType))
					continue;
				Move(c, o);
				any = true;
			}
			return any;
		}

		static TypeDef First(HashSet<TypeDef> set) {
			foreach (var t in set)
				return t;
			return null;
		}

		/// Leo qua các type compiler-generated đang nested tới class "thật" chứa nó; null nếu dừng ở holder.
		static TypeDef OwnerOf(TypeDef type) {
			var t = type;
			while (t != null && IsCompilerGenerated(t)) {
				if (t.DeclaringType == null)
					return null;
				t = t.DeclaringType;
			}
			return t;
		}

		static TypeDef GetReferencedType(object operand) {
			switch (operand) {
			case IMethod m when m.DeclaringType != null:
				return m.DeclaringType.ResolveTypeDef();
			case IField f when f.DeclaringType != null:
				return f.DeclaringType.ResolveTypeDef();
			case ITypeDefOrRef t:
				return t.ResolveTypeDef();
			}
			return null;
		}

		/// <c>anc</c> có phải là tổ tiên (declaring type, nhiều cấp) của <c>type</c>.
		static bool IsAncestor(TypeDef type, TypeDef anc) {
			for (var t = type.DeclaringType; t != null; t = t.DeclaringType) {
				if (t == anc)
					return true;
			}
			return false;
		}

		static bool IsCompilerGenerated(TypeDef type) {
			if (type.Name.String.StartsWith("<"))
				return true;
			foreach (var ca in type.CustomAttributes) {
				if (ca.TypeFullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute")
					return true;
			}
			foreach (var iface in type.Interfaces) {
				var n = iface.Interface?.FullName;
				if (n == "System.Runtime.CompilerServices.IAsyncStateMachine")
					return true;
			}
			return false;
		}

		void Move(TypeDef type, TypeDef newOwner) {
			if (type.DeclaringType != null)
				type.DeclaringType.NestedTypes.Remove(type);
			else
				module.Types.Remove(type);

			var vis = type.Attributes & TypeAttributes.VisibilityMask;
			if (vis == TypeAttributes.Public)
				vis = TypeAttributes.NestedPublic;
			else if (vis == TypeAttributes.NotPublic)
				vis = TypeAttributes.NestedAssembly;
			type.Attributes = (type.Attributes & ~TypeAttributes.VisibilityMask) | vis;
			type.Namespace = UTF8String.Empty;

			// Trùng tên nested type trong chủ mới -> thêm "_" (IL cấm trùng tên trong cùng declaring type).
			var name = type.Name.String;
			while (HasNested(newOwner, type.Name.String))
				type.Name = (type.Name.String) + "_";

			newOwner.NestedTypes.Add(type);
			moved++;
			Logger.v("Re-nest: {0} -> {1}", Utils.RemoveNewlines(name), Utils.RemoveNewlines(newOwner.FullName));
		}

		static bool HasNested(TypeDef owner, string name) {
			foreach (var n in owner.NestedTypes) {
				if (n.Name.String == name)
					return true;
			}
			return false;
		}
	}
}
