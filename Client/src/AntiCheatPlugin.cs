using BepInEx;
using BepInEx.Bootstrap;
using EFT.UI;
using UnityEngine;
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

    // UnityEngine.UIModule.dll 官方 MD5 哈希值。
    private readonly string _officialUIModuleHash = "fb779dd1543296fdf61d1101ff854189";

    private void Awake()
    {
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
            return;
        }

        // CrashAfterAcknowledgement(
        //     $"MAC_Client startup check failed. Missing Chainloader plugin(s): {string.Join(", ", missing)}");
        
        CrashAfterAcknowledgement(
            $"FIKA CORE 客户端校验失败");
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
}
