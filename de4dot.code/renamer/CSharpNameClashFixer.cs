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

namespace de4dot.code.renamer {
	/// <summary>
	/// Đổi tên tối thiểu những member mà IL cho phép nhưng C# cấm, để output decompile compile lại được
	/// khi đã giữ tên (--keep-names / WPF giữ tên cho BAML):
	///   - CS0542: member (field/method/property/event/nested type) trùng tên type bao nó.
	///   - CS0102: field/property/event/nested type trùng tên một member khác loại trong cùng type
	///     (overload method với nhau thì hợp lệ, không đụng).
	/// Chỉ đổi member KHÔNG nhìn thấy từ ngoài assembly (assembly khác có thể tham chiếu theo tên),
	/// không đổi method (có thể là override/implement interface). Tham chiếu trong module là token -> tự theo.
	/// </summary>
	public class CSharpNameClashFixer {
		readonly ModuleDef module;
		DefRenamer renamer;
		int renamed, skipped;

		public CSharpNameClashFixer(ModuleDef module) => this.module = module;

		public void Fix() {
			renamer = new DefRenamer(module);
			foreach (var type in module.GetTypes())
				FixType(type);
			if (renamed != 0)
				module.ResetTypeDefFindCache();
			if (renamed != 0 || skipped != 0)
				Logger.n("C# name clashes: renamed {0}, skipped {1} (externally visible)", renamed, skipped);
		}

		static string CsName(string name) {
			int i = name.IndexOf('`');
			return i < 0 ? name : name.Substring(0, i);
		}

		void FixType(TypeDef type) {
			var typeName = CsName(type.Name.String);

			// CS0542 cho method: chỉ đổi khi không virtual (không override/implement) và không nhìn thấy từ ngoài.
			foreach (var m in type.Methods) {
				if (m.IsConstructor || m.Name.String != typeName)
					continue;
				if (m.IsVirtual || m.HasOverrides || IsVisible(m) && IsTypeVisible(type)) {
					skipped++;
					continue;
				}
				renamer.Rename(m, typeName + "_");
				Logger.v("C# name clash: {0} => {1}", Utils.RemoveNewlines(m.FullName), m.Name);
				renamed++;
			}

			// Tên đang dùng bởi method (giữ nguyên), và đếm theo loại để tìm va chạm.
			var methodNames = new HashSet<string>();
			foreach (var m in type.Methods)
				if (!m.IsConstructor)
					methodNames.Add(m.Name.String);

			var taken = new HashSet<string>(methodNames) { typeName };
			foreach (var gp in type.GenericParameters)
				taken.Add(gp.Name.String);

			// Thứ tự ưu tiên giữ tên: nested type, property, event, field (field đổi trước nhất).
			var members = new List<IMemberDef>();
			members.AddRange(type.NestedTypes);
			members.AddRange(type.Properties);
			members.AddRange(type.Events);
			members.AddRange(type.Fields);

			// Event "field-like" có backing field trùng tên event -> ilspy gộp lại, không phải va chạm.
			var eventNames = new HashSet<string>();
			foreach (var e in type.Events)
				eventNames.Add(e.Name.String);

			// Nested type với nhau được trùng tên nếu KHÁC arity (Foo và Foo<T> hợp lệ trong C#) -> so theo tên
			// metadata có `N. Nested type với member khác loại thì so theo tên C# (bỏ `N).
			var typeKeys = new HashSet<string>();
			var nestedNames = new HashSet<string>();

			foreach (var member in members) {
				var td = member as TypeDef;
				var name = td != null ? CsName(td.Name.String) : member.Name.String;
				bool isEventBackingField = member is FieldDef && eventNames.Contains(name);
				if (isEventBackingField)
					continue;
				bool clash = td != null
					? taken.Contains(name) || typeKeys.Contains(td.Name.String)
					: taken.Contains(name) || nestedNames.Contains(name);
				if (!clash) {
					if (td != null) {
						typeKeys.Add(td.Name.String);
						nestedNames.Add(name);
					}
					else
						taken.Add(name);
					continue;
				}
				if (IsExternallyVisible(member)) {
					skipped++;
					taken.Add(name);
					continue;
				}
				var newName = name + "_";
				while (taken.Contains(newName) || nestedNames.Contains(newName))
					newName += "_";
				if (td != null)
					nestedNames.Add(newName);
				if (member is TypeDef nt) {
					int tick = nt.Name.String.IndexOf('`');
					renamer.Rename(nt, tick < 0 ? newName : newName + nt.Name.String.Substring(tick));
				}
				else
					renamer.Rename(member, newName);
				Logger.v("C# name clash: {0} => {1}", Utils.RemoveNewlines(member.FullName), Utils.RemoveNewlines(newName));
				taken.Add(newName);
				renamed++;
			}
		}

		static bool IsTypeVisible(TypeDef type) {
			for (var t = type; t != null; t = t.DeclaringType) {
				if (t.IsNested) {
					if (!(t.IsNestedPublic || t.IsNestedFamily || t.IsNestedFamilyOrAssembly))
						return false;
				}
				else if (!t.IsPublic)
					return false;
			}
			return true;
		}

		static bool IsExternallyVisible(IMemberDef member) {
			if (member is TypeDef td)
				return IsTypeVisible(td);
			if (!IsTypeVisible(member.DeclaringType))
				return false;
			switch (member) {
			case FieldDef f:
				return f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly;
			case PropertyDef p:
				return IsVisible(p.GetMethod) || IsVisible(p.SetMethod);
			case EventDef e:
				return IsVisible(e.AddMethod) || IsVisible(e.RemoveMethod);
			}
			return true;
		}

		static bool IsVisible(MethodDef m) => m != null && (m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly);
	}
}
