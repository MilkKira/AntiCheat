using HarmonyLib;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.DI;
using SPTarkov.Server.Core.Models.Utils;
using SPTarkov.Server.Core.Utils;

namespace Milkkira.AntiCheat.Server;

// SPT 通过 DI 创建此类并在模组加载阶段调用 OnLoad。
// 这里负责把静态拦截器需要的工具对象注入 ClientModGate，并一次性安装 Harmony 补丁。
[Injectable]
public sealed class AntiCheatBootstrap : IOnLoad
{
    // 防止 SPT 重载或重复调用 OnLoad 时重复 PatchAll。
    private static bool _patched;

    private readonly HttpResponseUtil _httpResponseUtil;
    private readonly ISptLogger<AntiCheatBootstrap> _logger;

    public AntiCheatBootstrap(HttpResponseUtil httpResponseUtil, ISptLogger<AntiCheatBootstrap> logger)
    {
        _httpResponseUtil = httpResponseUtil;
        _logger = logger;
    }

    public Task OnLoad()
    {
        if (_patched) return Task.CompletedTask;

        // 静态 patch 类不能走构造函数注入，因此先把 SPT 工具对象保存到 ClientModGate。
        ClientModGate.Configure(_httpResponseUtil, _logger);
        AntiCheatAuditStore.Configure(_logger);

        // 使用服务端 GUID 作为 Harmony 实例 id，便于后续排查补丁归属。
        var harmony = new Harmony(AntiCheatConstants.ServerGuid);

        // 扫描当前程序集内所有 [HarmonyPatch] 类并安装补丁。
        harmony.PatchAll(typeof(AntiCheatBootstrap).Assembly);

        _patched = true;

        // 日志从常量生成，避免常量改名后日志仍显示旧 GUID。
        _logger.Info(
            $"[AntiCheat] Server gate loaded. Required client plugins: {string.Join(", ", AntiCheatConstants.RequiredClientPluginGuids)}");

        return Task.CompletedTask;
    }
}
