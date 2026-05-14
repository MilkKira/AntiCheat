using System.Net.WebSockets;
using HarmonyLib;
using Microsoft.AspNetCore.Http;
using SPTarkov.Server.Core.Callbacks;
using SPTarkov.Server.Core.Controllers;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Eft.Game;
using SPTarkov.Server.Core.Models.Eft.Notifier;
using SPTarkov.Server.Core.Servers.Http;
using SPTarkov.Server.Core.Servers.Ws;

namespace Milkkira.AntiCheat.Server;

// 服务端主闸门：ReceiveClientMods 一旦把 session 标记为拒绝，后续所有普通 HTTP 请求都会在这里被拦下。
// 拦在 SptHttpListener.Handle 的好处是足够靠前，可以阻止请求继续进入 SPT 的路由、回调和资料处理逻辑。
[HarmonyPatch(typeof(SptHttpListener), "Handle", typeof(MongoId), typeof(HttpContext))]
internal static class SptHttpListenerHandlePatch
{
    private static bool Prefix(
        MongoId sessionId,
        HttpContext context,
        ref Task __result)
    {
        // if (!ClientModGate.IsRejected(sessionId, out var reason))
        // {
        //     AntiCheatAuditStore.RecordHttpRequest(sessionId, context, "allowed");
        //     return true;
        // }
        if (!ClientModGate.IsRejected(sessionId, out var reason)) return true;

        // 保留 clientmods 放行：玩家补回 Fika/AntiCheat 客户端后，可以重新上报插件列表并解除拒绝状态。
        if (ClientModGate.IsClientModsRequest(context))
        {
            AntiCheatAuditStore.RecordHttpRequest(sessionId, context, "allowed_clientmods_recheck", reason);
            return true;
        }

        // 返回 false 表示跳过原始 Handle；__result 指向我们自己的 403 写回任务。
        __result = ClientModGate.RejectHttpRequestAsync(context, sessionId, reason);
        return false;
    }
}

// 第一道信任判断：Fika 在此接口上报客户端 Chainloader 插件列表。
// 缺少 Fika.Core 或 AntiCheat Client 时，直接把 session 写入拒绝表。
[HarmonyPatch(typeof(GameCallbacks), nameof(GameCallbacks.ReceiveClientMods))]
internal static class ReceiveClientModsPatch
{
    private static bool Prefix(
        SendClientModsRequest request,
        MongoId sessionID,
        ref ValueTask<string> __result)
    {
        if (ClientModGate.ValidateClientMods(request, sessionID, out var rejectionMessage)) return true;

        // 首次校验失败时，直接返回 SPT 风格错误包，不继续执行原始 ReceiveClientMods。
        __result = new ValueTask<string>(ClientModGate.BuildRejectBody(rejectionMessage));
        return false;
    }
}

// Notifier 兜底：如果客户端在被拒绝前已经尝试获取通知通道，就把通道地址改成无效地址。
// 这不是主拦截点，只是防止被拒绝客户端继续拿到正常 notifier / websocket 地址。
[HarmonyPatch(typeof(NotifierController), nameof(NotifierController.GetChannel))]
internal static class NotifierChannelPatch
{
    private static void Postfix(MongoId sessionId, NotifierChannel __result)
    {
        ClientModGate.StampRejectedNotifierChannel(sessionId, __result);
    }
}

// WebSocket 兜底：长连接入口不一定会完整经过普通 HTTP 路由处理。
// 已拒绝 session 如果继续发起 websocket 连接，就在这里主动关闭，避免保留实时通知/联机通道。
[HarmonyPatch(typeof(SptWebSocketConnectionHandler), nameof(SptWebSocketConnectionHandler.OnConnection))]
internal static class SptWebSocketConnectionPatch
{
    private static bool Prefix(
        WebSocket ws,
        HttpContext context,
        ref Task __result)
    {
        if (!ClientModGate.TryGetRejectedSessionFromPath(context, out var sessionId, out var reason)) return true;

        AntiCheatAuditStore.RecordWebSocketRequest(context, sessionId, "rejected", reason);
        ClientModGate.LogRejectedWebSocket(sessionId, reason);
        __result = ClientModGate.CloseRejectedWebSocketAsync(ws, reason);
        return false;
    }
}
