namespace Milkkira.AntiCheat.Server;

// 统一保存服务端和客户端都需要识别的 GUID。
// 后续如果改插件 GUID，只需要优先检查这里和客户端 BepInPlugin 是否一致。
internal static class AntiCheatConstants
{
    // 服务端 GUID 同时用于 SPT 模组标识和 Harmony 实例 id。
    public const string ServerGuid = "com.milkkira.anticheat.server";

    // 客户端 BepInEx 插件 GUID，必须和客户端 AntiCheatPlugin.PluginGuid 保持一致。
    public const string ClientGuid = "com.milkkira.anticheat.client";

    // Fika.Core 的 BepInEx GUID；服务端通过 clientmods 上报结果确认它是否在 Chainloader 中。
    public const string FikaGuid = "com.fika.core";

    // 服务端强制要求客户端加载的插件列表。
    // ReceiveClientModsPatch 会用此列表判断是否拒绝 session。
    public static readonly string[] RequiredClientPluginGuids =
    [
        FikaGuid
    ];
}
