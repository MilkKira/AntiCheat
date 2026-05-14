using System.Reflection;
using System.Text.Json;
using SPTarkov.Server.Core.Models.Utils;

namespace Milkkira.AntiCheat.Server;

// AntiCheatSettings 是服务端握手策略的唯一配置来源。
// 配置文件会生成在服务端模组 DLL 所在目录，便于服务器管理员直接随模组一起部署和备份。
internal sealed class AntiCheatSettings
{
    private const string SettingsFileName = "anticheat-settings.json";
    private const string DefaultSharedSecret = "change-me-milkkira-anticheat";

    public string SharedSecret { get; set; } = DefaultSharedSecret;

    // 允许加载的客户端 BepInEx 插件 GUID。只要客户端上报的 GUID 不在这里，就会被拒绝。
    public string[] AllowedMods { get; set; } =
    [
        AntiCheatConstants.FikaGuid,
        AntiCheatConstants.ClientGuid
    ];

    // 必须加载的客户端 BepInEx 插件 GUID。缺少任意一个都会拒绝。
    public string[] RequiredMods { get; set; } = AntiCheatConstants.RequiredClientPluginGuids;

    // 明确禁止加载的客户端 BepInEx 插件 GUID。命中任意一个都会拒绝。
    public string[] BannedMods { get; set; } = [];

    // 客户端从领取挑战码到完成验证的最大秒数。原版客户端不会请求验证，因此会在这里超时。
    public int ChallengeTimeoutSeconds { get; set; } = 10;

    // 客户端时间戳允许和服务端 UTC 时间相差的最大秒数，用来降低旧消息重放风险。
    public int TimestampToleranceSeconds { get; set; } = 30;

    public static AntiCheatSettings Load(ISptLogger<AntiCheatBootstrap> logger)
    {
        var path = GetSettingsPath();

        AntiCheatSettings settings;
        if (!File.Exists(path))
        {
            settings = new AntiCheatSettings();
            WriteSettingsFile(path, settings);
            logger.Warning($"[AntiCheat] Created default settings file, please change SharedSecret before public deployment: {path}");
        }
        else
        {
            var json = File.ReadAllText(path);
            settings = JsonSerializer.Deserialize<AntiCheatSettings>(json, JsonOptions) ?? new AntiCheatSettings();
        }

        settings.Normalize();

        if (string.Equals(settings.SharedSecret, DefaultSharedSecret, StringComparison.Ordinal))
            logger.Warning("[AntiCheat] SharedSecret is still the default value. Change it on both server and client config before public deployment.");

        return settings;
    }

    private static void WriteSettingsFile(string path, AntiCheatSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? AppContext.BaseDirectory);
        File.WriteAllText(path, JsonSerializer.Serialize(settings, JsonOptions));
    }

    private static string GetSettingsPath()
    {
        var assemblyDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        var directory = string.IsNullOrWhiteSpace(assemblyDirectory) ? AppContext.BaseDirectory : assemblyDirectory;
        return Path.Combine(directory, SettingsFileName);
    }

    private void Normalize()
    {
        SharedSecret = string.IsNullOrWhiteSpace(SharedSecret) ? DefaultSharedSecret : SharedSecret.Trim();
        AllowedMods = NormalizeGuidList(AllowedMods);
        RequiredMods = NormalizeGuidList(RequiredMods);
        BannedMods = NormalizeGuidList(BannedMods);
        ChallengeTimeoutSeconds = Math.Clamp(ChallengeTimeoutSeconds, 3, 120);
        TimestampToleranceSeconds = Math.Clamp(TimestampToleranceSeconds, 5, 300);
    }

    private static string[] NormalizeGuidList(IEnumerable<string>? values)
    {
        return values?
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray()
            ?? [];
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };
}
