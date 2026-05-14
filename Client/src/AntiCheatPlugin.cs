using BepInEx;
using BepInEx.Bootstrap;
using BepInEx.Configuration;
using EFT.UI;
using UnityEngine;
using UnityEngine.Networking;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Collections;

namespace Milkkira.AntiCheat.Client;

[BepInPlugin(PluginGuid, PluginName, PluginVersion)]
[BepInDependency(FikaGuid, BepInDependency.DependencyFlags.SoftDependency)]
public sealed class AntiCheatPlugin : BaseUnityPlugin
{
    public const string PluginGuid = "com.milkkira.anticheat.client";
    
    public const string PluginName = "Milkkira.AntiCheat.Client";
    
    public const string PluginVersion = "1.0.0";

    private const string FikaGuid = "com.fika.core";

    private const string DefaultSharedSecret = "change-me-milkkira-anticheat";

    // UnityEngine.UIModule.dll 官方 MD5 哈希值。
    private readonly string _officialUIModuleHash = "fb779dd1543296fdf61d1101ff854189";

    private ConfigEntry<string>? _serverUrlConfig;
    private ConfigEntry<string>? _sharedSecretConfig;
    private ConfigEntry<int>? _handshakeTimeoutConfig;

    private void Awake()
    {
        // ServerUrl 留空时会读取 EFT/SPT 自己的后端地址；只有特殊代理部署才需要手动填写。
        _serverUrlConfig = Config.Bind("Server", "ServerUrl", string.Empty, "SPT 服务端地址，留空则读取游戏当前 BackendUrl。");
        _sharedSecretConfig = Config.Bind("Server", "SharedSecret", DefaultSharedSecret, "必须和服务端 anticheat-settings.json 中的 SharedSecret 完全一致。");
        _handshakeTimeoutConfig = Config.Bind("Server", "HandshakeTimeoutSeconds", 10, "客户端请求挑战码和回传指纹时使用的网络超时秒数。");

        bool verifyUnityUIModule = !this.VerifyUnityEngineUIModule();
        
        
        if (verifyUnityUIModule)
        {
            Logger.LogError("[MAC] The core file verification failed, and the game was about to quit!");
            CrashAfterAcknowledgement(
                $"核心文件校验失败");
        }
        
        // if (this.ScanForMaliciousModules())
        // {
        //     Logger.LogError("[MAC] A malicious module is detected and the game is about to quit!");
        //     CrashAfterAcknowledgement(
        //         $"游戏文件校验失败");
        // }
        
        // 保持 Fika 作为软依赖，避免 Fika 被移除时本插件也被 BepInEx 跳过加载。
        var missing = new[] { FikaGuid, PluginGuid }
            .Where(requiredGuid => !Chainloader.PluginInfos.ContainsKey(requiredGuid))
            .ToArray();

        if (missing.Length == 0)
        {
            Logger.LogInfo("[MAC] Boot Successful!");
            StartCoroutine(RunServerHandshake());
            return;
        }

        // CrashAfterAcknowledgement(
        //     $"MAC_Client startup check failed. Missing Chainloader plugin(s): {string.Join(", ", missing)}");
        
        CrashAfterAcknowledgement(
            $"FIKA CORE 客户端校验失败");
    }

    private IEnumerator RunServerHandshake()
    {
        var serverUrl = ResolveServerUrl();
        if (string.IsNullOrWhiteSpace(serverUrl))
        {
            CrashAfterAcknowledgement("反作弊握手失败：无法识别 SPT 服务端地址。");
            yield break;
        }

        // 第一步：从服务端领取一次性挑战码。原版客户端不会访问这个接口，服务端会因此在 10 秒后拒绝它。
        using var challengeRequest = UnityWebRequest.Get($"{serverUrl}/anticheat/challenge");
        challengeRequest.timeout = Math.Max(3, _handshakeTimeoutConfig?.Value ?? 10);
        yield return challengeRequest.SendWebRequest();

        if (IsRequestFailed(challengeRequest))
        {
            CrashAfterAcknowledgement($"反作弊握手失败：无法领取挑战码（{ReadWebError(challengeRequest)}）。");
            yield break;
        }

        var challengeResponse = JsonUtility.FromJson<ChallengeResponse>(challengeRequest.downloadHandler.text);
        if (challengeResponse is null || !challengeResponse.success || string.IsNullOrWhiteSpace(challengeResponse.challenge))
        {
            CrashAfterAcknowledgement($"反作弊握手失败：服务端挑战码无效（{challengeResponse?.reason ?? "empty response"}）。");
            yield break;
        }

        // 第二步：上报 Chainloader 中所有已加载插件 GUID，并对挑战码、时间戳和插件列表计算 HMAC。
        var mods = Chainloader.PluginInfos.Keys
            .Where(guid => !string.IsNullOrWhiteSpace(guid))
            .Select(guid => guid.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(guid => guid, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var verifyBody = new VerifyRequest
        {
            challenge = challengeResponse.challenge,
            timestamp = timestamp,
            mods = mods,
            hmac = ComputeHandshakeHmac(challengeResponse.challenge, timestamp, mods)
        };

        using var verifyRequest = new UnityWebRequest($"{serverUrl}/anticheat/verify", UnityWebRequest.kHttpVerbPOST);
        var bodyBytes = Encoding.UTF8.GetBytes(JsonUtility.ToJson(verifyBody));
        verifyRequest.uploadHandler = new UploadHandlerRaw(bodyBytes);
        verifyRequest.downloadHandler = new DownloadHandlerBuffer();
        verifyRequest.timeout = Math.Max(3, _handshakeTimeoutConfig?.Value ?? 10);
        verifyRequest.SetRequestHeader("Content-Type", "application/json");
        yield return verifyRequest.SendWebRequest();

        var verifyResponse = JsonUtility.FromJson<VerifyResponse>(verifyRequest.downloadHandler.text);
        if (IsRequestFailed(verifyRequest) || verifyResponse is null || !verifyResponse.success)
        {
            var reason = verifyResponse?.reason;
            if (string.IsNullOrWhiteSpace(reason)) reason = ReadWebError(verifyRequest);
            CrashAfterAcknowledgement($"反作弊握手失败：{reason}");
            yield break;
        }

        Logger.LogInfo("[MAC] Server handshake verified.");
    }

    private string ResolveServerUrl()
    {
        var configured = _serverUrlConfig?.Value;
        if (!string.IsNullOrWhiteSpace(configured)) return configured.Trim().TrimEnd('/');

        try
        {
            var backendUrl = BackendConfigAbstractClass.BackendUrl;
            if (!string.IsNullOrWhiteSpace(backendUrl)) return backendUrl.Trim().TrimEnd('/');
        }
        catch (Exception exception)
        {
            Logger.LogWarning($"[MAC] Unable to read BackendUrl from EFT: {exception.Message}");
        }

        return "http://127.0.0.1:6969";
    }

    private string ComputeHandshakeHmac(string challenge, long timestamp, string[] mods)
    {
        var payload = challenge + "\n" + timestamp + "\n" + string.Join("\n", mods);
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_sharedSecretConfig?.Value ?? DefaultSharedSecret));
        return BitConverter.ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).Replace("-", string.Empty).ToLowerInvariant();
    }

    private static bool IsRequestFailed(UnityWebRequest request)
    {
        return request.result != UnityWebRequest.Result.Success;
    }

    private static string ReadWebError(UnityWebRequest request)
    {
        if (!string.IsNullOrWhiteSpace(request.downloadHandler?.text)) return request.downloadHandler.text;
        if (!string.IsNullOrWhiteSpace(request.error)) return request.error;
        return $"HTTP {request.responseCode}";
    }

    private void CrashAfterAcknowledgement(string message)
    {
        Logger.LogError($"[MAC] {message}");
        StartCoroutine(ShowEftErrorAndCrash(message));
    }

    private IEnumerator ShowEftErrorAndCrash(string message)
    {
        // 只使用EFT自带的预加载错误界面。唤醒可以比这个界面更早运行
        // 所以等单例出现时再展示 EFT 错误界面。
        while (!PreloaderUI.Instantiated) yield return null;

        PreloaderUI.Instance.ShowErrorScreen(
            PluginName,
            $"{message}\n\n 游戏即将退出！",
            () =>
            {
                // 先让Unity干净地退出，然后强制快速终止  
                Application.Quit(403);
                Environment.FailFast(message);
            });
    }
    
    private bool VerifyUnityEngineUIModule()
    {
        string text = Path.Combine(Path.Combine(Application.dataPath, "Managed"), "UnityEngine.UIModule.dll");
        bool flag;
        if (!File.Exists(text))
        {
             Logger.LogError("[MAC] UnityEngine.UIModule Not Existed: " + text);
            flag = false;
        }
        else
        {
            string text2 = this.CalculateMD5(text);
            if (text2 != this._officialUIModuleHash)
            {
                 Logger.LogError("[MAC] File Hash Matched Failed！target: " + this._officialUIModuleHash + "，Now: " + text2);
                flag = false;
            }
            else
            {
                 Logger.LogInfo("[MAC] UnityEngine.UIModule.dll Verified");
                flag = true;
            }
        }
        return flag;
    }
    
    private string CalculateMD5(string filename)
    {
        string text;
        using (MD5 md = MD5.Create())
        {
            using (FileStream fileStream = File.OpenRead(filename))
            {
                byte[] array = md.ComputeHash(fileStream);
                StringBuilder stringBuilder = new StringBuilder();
                foreach (byte b in array)
                {
                    stringBuilder.Append(b.ToString("x2"));
                }
                text = stringBuilder.ToString();
            }
        }
        return text;
    }
    
    private bool ScanForMaliciousModules()
    {
        foreach (object obj in Process.GetCurrentProcess().Modules)
        {
            ProcessModule processModule = (ProcessModule)obj;
            string text = processModule.ModuleName.ToLowerInvariant();
            if (text.Contains("tt.dll") || 
                (text.Contains("cheat") && !text.Contains("anticheat")) || 
                text.Contains("yy.dll"))
            {
                Logger.LogError("discover malicious modules " + processModule.ModuleName);
                return true;
            }
        }
        Logger.LogInfo("no malicious modules found");
        return false;
    }

    // 下面两个响应类型由 Unity JsonUtility 反序列化赋值，编译器无法静态看见这些字段写入。
#pragma warning disable CS0649
    [Serializable]
    private sealed class ChallengeResponse
    {
        public bool success;
        public string? reason;
        public string? challenge;
        public string? expiresAtUtc;
        public int timeoutSeconds;
    }

    [Serializable]
    private sealed class VerifyRequest
    {
        public string? challenge;
        public long timestamp;
        public string? hmac;
        public string[] mods = [];
    }

    [Serializable]
    private sealed class VerifyResponse
    {
        public bool success;
        public string? reason;
    }
#pragma warning restore CS0649
}
