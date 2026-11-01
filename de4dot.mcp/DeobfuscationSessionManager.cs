namespace de4dot.mcp {
	public class DeobfuscationSessionManager {
		// Transport stdio không có SessionId (null): một tiến trình = một client -> dùng chung một khoá.
		const string StdioSession = "stdio";

		private readonly Dictionary<string, DeobfuscationSession> sessions = new();

		public DeobfuscationSession GetSession(string? name) {
			name ??= StdioSession;
			lock (sessions) {
				if (!sessions.TryGetValue(name, out var session))
					sessions[name] = session = new DeobfuscationSession();
				return session;
			}
		}
	}
}
