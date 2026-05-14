using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Utils;
using SQLitePCL;

namespace Milkkira.AntiCheat.Server;

// AntiCheatAuditStore 负责把服务端看到的访问记录落到 SQLite。
// 这里不保存请求正文，避免把登录令牌、存档数据或其它敏感业务内容写进审计库。
internal static class AntiCheatAuditStore
{
    private const int MaxTextLength = 2048;
    private const string DatabaseFileName = "anticheat-audit.sqlite3";

    private static readonly object SyncRoot = new();

    private static ISptLogger<AntiCheatBootstrap>? _logger;
    private static string? _connectionString;
    private static bool _initialized;

    public static void Configure(ISptLogger<AntiCheatBootstrap> logger)
    {
        _logger = logger;
        ConfigureNativeSqliteResolver();
        Batteries_V2.Init();

        // 数据库放在当前服务端模组 DLL 所在目录，方便随模组一起备份/迁移。
        var assemblyDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        var databaseDirectory = string.IsNullOrWhiteSpace(assemblyDirectory)
            ? AppContext.BaseDirectory
            : assemblyDirectory;

        Directory.CreateDirectory(databaseDirectory);

        var databasePath = Path.Combine(databaseDirectory, DatabaseFileName);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();

        lock (SyncRoot)
        {
            if (_initialized) return;

            using var connection = OpenConnection();

            ExecuteNonQuery(connection, "PRAGMA journal_mode=WAL;");
            ExecuteNonQuery(connection, "PRAGMA busy_timeout=5000;");
            ExecuteNonQuery(
                connection,
                """
                CREATE TABLE IF NOT EXISTS access_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at_utc TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    profile_id TEXT NULL,
                    ip_address TEXT NULL,
                    forwarded_for TEXT NULL,
                    method TEXT NULL,
                    path TEXT NULL,
                    query_string TEXT NULL,
                    host TEXT NULL,
                    user_agent TEXT NULL,
                    trace_id TEXT NULL,
                    reason TEXT NULL
                );
                """);

            ExecuteNonQuery(connection, "CREATE INDEX IF NOT EXISTS ix_access_events_created_at_utc ON access_events(created_at_utc);");
            ExecuteNonQuery(connection, "CREATE INDEX IF NOT EXISTS ix_access_events_session_id ON access_events(session_id);");
            ExecuteNonQuery(connection, "CREATE INDEX IF NOT EXISTS ix_access_events_profile_id ON access_events(profile_id);");
            ExecuteNonQuery(connection, "CREATE INDEX IF NOT EXISTS ix_access_events_ip_address ON access_events(ip_address);");

            _initialized = true;
        }

        _logger?.Info($"[AntiCheat] SQLite access audit enabled: {databasePath}");
    }

    private static void ConfigureNativeSqliteResolver()
    {
        // SPT 会把 mod 目录里的 dll 当托管程序集扫描，所以 e_sqlite3.dll 不能放在 user/mods 下。
        // 这里把 SQLite 原生库固定加载为 SPT 程序根目录下的 e_sqlite3.dll。
        try
        {
            NativeLibrary.SetDllImportResolver(
                typeof(SQLite3Provider_e_sqlite3).Assembly,
                (libraryName, _, _) =>
                {
                    if (!libraryName.Equals("e_sqlite3", StringComparison.OrdinalIgnoreCase)
                        && !libraryName.Equals("e_sqlite3.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        return IntPtr.Zero;
                    }

                    var nativePath = Path.Combine(AppContext.BaseDirectory, "e_sqlite3.dll");
                    return NativeLibrary.TryLoad(nativePath, out var handle) ? handle : IntPtr.Zero;
                });
        }
        catch (InvalidOperationException)
        {
            // 同一个程序集只能设置一次 resolver；如果其它组件已经设置过，就继续使用现有 resolver。
        }
    }

    public static void RecordHttpRequest(MongoId sessionId, HttpContext context, string decision, string? reason = null)
    {
        var sessionKey = sessionId.ToString();

        Enqueue(
            new AccessEvent(
                EventType: "http_request",
                Decision: decision,
                SessionId: sessionKey,
                ProfileId: ResolveProfileId(sessionKey, context),
                IpAddress: Limit(context.Connection.RemoteIpAddress?.ToString()),
                ForwardedFor: Limit(ReadHeader(context, "X-Forwarded-For")),
                Method: Limit(context.Request.Method),
                Path: Limit(context.Request.Path.Value),
                QueryString: Limit(context.Request.QueryString.Value),
                Host: Limit(context.Request.Host.Value),
                UserAgent: Limit(ReadHeader(context, "User-Agent")),
                TraceId: Limit(context.TraceIdentifier),
                Reason: Limit(reason)));
    }

    public static void RecordClientModCheck(MongoId sessionId, string decision, string? reason = null)
    {
        var sessionKey = sessionId.ToString();

        Enqueue(
            new AccessEvent(
                EventType: "clientmods_check",
                Decision: decision,
                SessionId: sessionKey,
                ProfileId: sessionKey,
                IpAddress: null,
                ForwardedFor: null,
                Method: "POST",
                Path: "/singleplayer/clientmods",
                QueryString: null,
                Host: null,
                UserAgent: null,
                TraceId: null,
                Reason: Limit(reason)));
    }

    public static void RecordWebSocketRequest(HttpContext context, string sessionId, string decision, string? reason = null)
    {
        Enqueue(
            new AccessEvent(
                EventType: "websocket_request",
                Decision: decision,
                SessionId: Limit(sessionId) ?? string.Empty,
                ProfileId: ResolveProfileId(sessionId, context),
                IpAddress: Limit(context.Connection.RemoteIpAddress?.ToString()),
                ForwardedFor: Limit(ReadHeader(context, "X-Forwarded-For")),
                Method: Limit(context.Request.Method),
                Path: Limit(context.Request.Path.Value),
                QueryString: Limit(context.Request.QueryString.Value),
                Host: Limit(context.Request.Host.Value),
                UserAgent: Limit(ReadHeader(context, "User-Agent")),
                TraceId: Limit(context.TraceIdentifier),
                Reason: Limit(reason)));
    }

    private static void Enqueue(AccessEvent accessEvent)
    {
        // 拦截补丁运行在请求线程上，写库失败不能影响游戏请求处理，所以这里用后台任务并在内部吞掉异常。
        _ = Task.Run(() => Insert(accessEvent));
    }

    private static void Insert(AccessEvent accessEvent)
    {
        try
        {
            if (!_initialized || string.IsNullOrWhiteSpace(_connectionString)) return;

            lock (SyncRoot)
            {
                using var connection = OpenConnection();
                using var command = connection.CreateCommand();

                command.CommandText =
                    """
                    INSERT INTO access_events (
                        created_at_utc,
                        event_type,
                        decision,
                        session_id,
                        profile_id,
                        ip_address,
                        forwarded_for,
                        method,
                        path,
                        query_string,
                        host,
                        user_agent,
                        trace_id,
                        reason
                    ) VALUES (
                        $created_at_utc,
                        $event_type,
                        $decision,
                        $session_id,
                        $profile_id,
                        $ip_address,
                        $forwarded_for,
                        $method,
                        $path,
                        $query_string,
                        $host,
                        $user_agent,
                        $trace_id,
                        $reason
                    );
                    """;

                command.Parameters.AddWithValue("$created_at_utc", DateTimeOffset.UtcNow.ToString("O"));
                command.Parameters.AddWithValue("$event_type", accessEvent.EventType);
                command.Parameters.AddWithValue("$decision", accessEvent.Decision);
                command.Parameters.AddWithValue("$session_id", accessEvent.SessionId);
                AddNullable(command, "$profile_id", accessEvent.ProfileId);
                AddNullable(command, "$ip_address", accessEvent.IpAddress);
                AddNullable(command, "$forwarded_for", accessEvent.ForwardedFor);
                AddNullable(command, "$method", accessEvent.Method);
                AddNullable(command, "$path", accessEvent.Path);
                AddNullable(command, "$query_string", accessEvent.QueryString);
                AddNullable(command, "$host", accessEvent.Host);
                AddNullable(command, "$user_agent", accessEvent.UserAgent);
                AddNullable(command, "$trace_id", accessEvent.TraceId);
                AddNullable(command, "$reason", accessEvent.Reason);

                command.ExecuteNonQuery();
            }
        }
        catch (Exception exception)
        {
            _logger?.Warning($"[AntiCheat] Failed to write SQLite audit event: {exception.Message}");
        }
    }

    private static SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private static void ExecuteNonQuery(SqliteConnection connection, string commandText)
    {
        using var command = connection.CreateCommand();
        command.CommandText = commandText;
        command.ExecuteNonQuery();
    }

    private static void AddNullable(SqliteCommand command, string name, string? value)
    {
        command.Parameters.AddWithValue(name, string.IsNullOrWhiteSpace(value) ? DBNull.Value : value);
    }

    private static string? ResolveProfileId(string sessionId, HttpContext context)
    {
        // SPT 的 MongoId sessionId 通常就是玩家 profile id；如果代理或客户端额外传了 profile 头/查询参数，则优先记录它。
        var profileId =
            ReadHeader(context, "X-Profile-Id")
            ?? ReadHeader(context, "Profile-Id")
            ?? ReadQuery(context, "profileId")
            ?? ReadQuery(context, "profile_id")
            ?? sessionId;

        return Limit(profileId);
    }

    private static string? ReadHeader(HttpContext context, string name)
    {
        return context.Request.Headers.TryGetValue(name, out var value) ? value.ToString() : null;
    }

    private static string? ReadQuery(HttpContext context, string name)
    {
        return context.Request.Query.TryGetValue(name, out var value) ? value.ToString() : null;
    }

    private static string? Limit(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var trimmed = value.Trim();
        return trimmed.Length <= MaxTextLength ? trimmed : trimmed[..MaxTextLength];
    }

    private sealed record AccessEvent(
        string EventType,
        string Decision,
        string SessionId,
        string? ProfileId,
        string? IpAddress,
        string? ForwardedFor,
        string? Method,
        string? Path,
        string? QueryString,
        string? Host,
        string? UserAgent,
        string? TraceId,
        string? Reason);
}
