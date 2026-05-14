using System.Collections.Concurrent;
using System.Net.WebSockets;
using Microsoft.AspNetCore.Http;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Eft.Game;
using SPTarkov.Server.Core.Models.Eft.Notifier;
using SPTarkov.Server.Core.Models.Enums;
using SPTarkov.Server.Core.Models.Utils;
using SPTarkov.Server.Core.Utils;

namespace Milkkira.AntiCheat.Server;

// ClientModGate 负责把“客户端插件校验结果”转换成“后续请求是否放行”。
// 这里不直接依赖某个具体路由，而是维护 session 状态，供 HTTP、Notifier、WebSocket 三处补丁共同使用。
internal static class ClientModGate
{
    // SPT/Fika 会在启动早期通过此接口上报客户端 Chainloader 插件列表。
    // 即使 session 已经被拒绝，也保留这个接口放行，方便玩家补回客户端 DLL/Fika 后重新上报并解除拒绝状态。
    // private const string ClientModsPath = "/singleplayer/clientmods";
    
    private static readonly string[] AllowedPathPrefixes = new[]
    {
        "/singleplayer/clientmods",
        "/launcher"  // 以这个前缀开头的所有路径都放行
    };
    
    public static bool IsAllowedPath(HttpContext context)
    {
        var path = context.Request.Path.Value;
        if (string.IsNullOrWhiteSpace(path)) return false;

        // 检查是否以白名单前缀开头
        return AllowedPathPrefixes.Any(prefix => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    // 这两个地址是故意设置的客户端本机回环死地址。
    // 服务器把地址写进 NotifierChannel 后，真正尝试连接的是玩家客户端；因此 127.0.0.1 指玩家自己的电脑，不是云服务器。
    // 端口 9 通常没有服务监听，可以让被拒绝客户端快速连接失败，作为 HTTP 全局拒绝之外的兜底。
    private const string InvalidNotifierUrl = "http://127.0.0.1:9/anticheat/rejected";
    private const string InvalidWebSocketUrl = "ws://127.0.0.1:9/anticheat/rejected";

    // 拒绝状态按 MongoId 字符串保存；同一个玩家首次校验失败后，后续会继续访问多个 HTTP / WebSocket 路径。
    // 字典值保存拒绝原因，便于后续 403 响应和日志输出给出一致信息。
    private static readonly ConcurrentDictionary<string, string> RejectedSessions = new(StringComparer.Ordinal);

    // 已验证状态用于记录通过校验的 session，并在二次上报成功时清理旧拒绝状态。
    // 当前真正决定拦截的是 RejectedSessions，VerifiedSessions 主要服务日志和后续扩展。
    private static readonly ConcurrentDictionary<string, byte> VerifiedSessions = new(StringComparer.Ordinal);

    private static HttpResponseUtil? _httpResponseUtil;
    private static ISptLogger<AntiCheatBootstrap>? _logger;

    public static void Configure(HttpResponseUtil httpResponseUtil, ISptLogger<AntiCheatBootstrap> logger)
    {
        // 这两个对象来自 SPT 的 DI 容器。集中保存后，静态 Harmony patch 就能统一生成 SPT 风格响应和日志。
        _httpResponseUtil = httpResponseUtil;
        _logger = logger;
    }

    public static bool ValidateClientMods(
        SendClientModsRequest? request,
        MongoId sessionId,
        out string rejectionMessage)
    {
        // Fika 会通过 clientmods 请求携带客户端 BepInEx 插件列表。
        // 如果请求体或 ActiveClientMods 缺失，说明客户端没有正确上报，按不可信处理。
        var activeMods = request?.ActiveClientMods;
        if (activeMods is null)
        {
            rejectionMessage = "client did not report active BepInEx plugins";
            MarkRejected(sessionId, rejectionMessage);
            return false;
        }

        // GUID 不区分大小写，比对时统一放入 HashSet，避免因为大小写差异造成误拒绝。
        var loadedGuids = activeMods
            .Where(mod => !string.IsNullOrWhiteSpace(mod.GUID))
            .Select(mod => mod.GUID)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // RequiredClientPluginGuids 是服务端唯一的强制客户端插件清单。
        // 目前要求 Fika.Core 和 AntiCheat Client 都必须出现在 Chainloader 中。
        var missing = AntiCheatConstants.RequiredClientPluginGuids
            .Where(requiredGuid => !loadedGuids.Contains(requiredGuid))
            .ToArray();

        if (missing.Length == 0)
        {
            // 允许客户端重新上报后恢复：如果之前被拒绝，MarkVerified 会清除 RejectedSessions。
            MarkVerified(sessionId);
            AntiCheatAuditStore.RecordClientModCheck(sessionId, "verified");
            rejectionMessage = string.Empty;
            return true;
        }

        rejectionMessage = $"missing required client plugin(s): {string.Join(", ", missing)}";
        MarkRejected(sessionId, rejectionMessage);
        AntiCheatAuditStore.RecordClientModCheck(sessionId, "rejected", rejectionMessage);
        return false;
    }

    public static string BuildRejectBody(string reason)
    {
        var message = $"AntiCheat rejected this client: {reason}";

        // 优先使用 SPT 自带 HttpResponseUtil 生成标准错误包，客户端更容易按原有逻辑处理。
        // 兜底 JSON 用于极早期或测试场景，避免 DI 尚未注入时因为 null 直接抛异常。
        if (_httpResponseUtil is null) return $$"""{"err":403,"errmsg":"{{message}}","data":null}""";

        return _httpResponseUtil.GetBody<object?>(null, BackendErrorCodes.HTTPForbidden, message);
    }

    public static bool IsRejected(MongoId sessionId, out string reason)
    {
        // 所有入口统一通过这个方法判断 session 是否已经进入拒绝名单。
        return RejectedSessions.TryGetValue(sessionId.ToString(), out reason!);
    }

    public static bool IsClientModsRequest(HttpContext context)
    {
        // 只给 clientmods 留恢复通道，其它接口一旦 session 被拒绝就不再进入 SPT 路由。
        // return context.Request.Path.Equals(ClientModsPath, StringComparison.OrdinalIgnoreCase);
        
        return IsAllowedPath(context);
    }

    public static async Task RejectHttpRequestAsync(HttpContext context, MongoId sessionId, string reason)
    {
        var sessionKey = sessionId.ToString();

        AntiCheatAuditStore.RecordHttpRequest(sessionId, context, "rejected", reason);

        _logger?.Warning(
            $"[MilkAntiCheatExpert] Rejected HTTP request for session {sessionKey}: {context.Request.Method} {context.Request.Path} ({reason})");

        if (context.Response.HasStarted) return;

        // 在 HTTP listener 边界直接结束请求，避免进入 SPT 后续路由/控制器。
        // 这比单纯关闭 WebSocket 更彻底：资料读取、存档、交易、匹配等后续 HTTP 请求都会被统一拒绝。
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";

        await context.Response.WriteAsync(BuildRejectBody(reason));
    }

    public static bool TryGetRejectedSessionFromPath(HttpContext context, out string sessionId, out string reason)
    {
        sessionId = string.Empty;
        reason = string.Empty;

        // WebSocket 连接没有直接传 MongoId 参数，只能从请求路径中取最后一段 session id。
        // 如果未来 SPT 改了 WebSocket 路径格式，这里是优先需要检查的兼容点。
        var path = context.Request.Path.Value;
        if (string.IsNullOrWhiteSpace(path)) return false;

        var candidate = path.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
        if (candidate is null || !RejectedSessions.TryGetValue(candidate, out reason!)) return false;

        sessionId = candidate;
        return true;
    }

    public static void StampRejectedNotifierChannel(MongoId sessionId, NotifierChannel channel)
    {
        if (!IsRejected(sessionId, out _)) return;

        // 如果被拒绝客户端仍然走到 NotifierChannel 获取阶段，就把通知/长连接地址改成死地址。
        // 主防线仍是 SptHttpListenerHandlePatch；这里是针对“已提前拿到 channel”的兜底。
        channel.NotifierServer = InvalidNotifierUrl;
        channel.WebSocket = InvalidWebSocketUrl;
        channel.Url = string.Empty;
    }

    public static void LogRejectedWebSocket(string sessionId, string reason)
    {
        _logger?.Warning($"[MilkAntiCheatExpert] Blocked websocket for rejected session {sessionId}: {reason}");
    }

    public static async Task CloseRejectedWebSocketAsync(WebSocket socket, string reason)
    {
        // 主动关闭已拒绝 session 的 WebSocket，让客户端长连接侧也得到明确的策略拒绝。
        if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
            await socket.CloseAsync(
                WebSocketCloseStatus.PolicyViolation,
                $"AntiCheat rejected client: {reason}",
                CancellationToken.None);
    }

    private static void MarkVerified(MongoId sessionId)
    {
        var key = sessionId.ToString();
        VerifiedSessions.TryAdd(key, 0);

        // 支持“修复客户端后重新上报”：通过校验时移除旧拒绝记录，不需要重启服务器。
        if (RejectedSessions.TryRemove(key, out _))
            _logger?.Info($"[MilkAntiCheatExpert] Session {key} passed client plugin verification after a previous rejection.");
        else
            _logger?.Info($"[MilkAntiCheatExpert] Session {key} passed client plugin verification.");
    }

    private static void MarkRejected(MongoId sessionId, string reason)
    {
        var key = sessionId.ToString();

        // 一旦拒绝，VerifiedSessions 中的旧通过状态必须清理，避免状态互相矛盾。
        VerifiedSessions.TryRemove(key, out _);
        RejectedSessions[key] = reason;
        _logger?.Warning($"[MilkAntiCheatExpert] Rejected session {key}: {reason}");
    }
}
