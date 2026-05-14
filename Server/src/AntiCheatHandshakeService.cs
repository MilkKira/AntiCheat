using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Utils;

namespace Milkkira.AntiCheat.Server;

// AntiCheatHandshakeService 实现服务端和客户端配套插件之间的挑战-响应握手。
// 普通原版客户端不会访问 /anticheat/challenge 和 /anticheat/verify，因此会在宽限期结束后被拒绝。
internal static class AntiCheatHandshakeService
{
    private const string ChallengePath = "/anticheat/challenge";
    private const string VerifyPath = "/anticheat/verify";
    private const int ChallengeBytes = 32;

    private static readonly ConcurrentDictionary<string, PendingChallenge> PendingClients = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, byte> VerifiedSessions = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, byte> VerifiedFingerprints = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, string> RejectedFingerprints = new(StringComparer.Ordinal);

    private static AntiCheatSettings? _settings;
    private static ISptLogger<AntiCheatBootstrap>? _logger;

    public static void Configure(AntiCheatSettings settings, ISptLogger<AntiCheatBootstrap> logger)
    {
        _settings = settings;
        _logger = logger;
    }

    public static bool TryHandleEndpoint(MongoId sessionId, HttpContext context, out Task result)
    {
        if (context.Request.Path.Equals(ChallengePath, StringComparison.OrdinalIgnoreCase))
        {
            result = IssueChallengeAsync(sessionId, context);
            return true;
        }

        if (context.Request.Path.Equals(VerifyPath, StringComparison.OrdinalIgnoreCase))
        {
            result = VerifyResponseAsync(sessionId, context);
            return true;
        }

        result = Task.CompletedTask;
        return false;
    }

    public static bool IsRequestAllowed(MongoId sessionId, HttpContext context, out string rejectionReason)
    {
        rejectionReason = string.Empty;
        if (_settings is null) return true;

        var sessionKey = ResolveSessionKey(sessionId);
        var fingerprint = ResolveClientFingerprint(context);

        // 如果握手请求没有携带 SPT session，服务端会退回到 IP 指纹标记。
        // 后续普通请求只要同一来源已经通过握手，就会把当前 session 一并标记为通过。
        if (IsVerified(sessionKey, fingerprint))
        {
            ClientModGate.MarkHandshakeVerified(sessionId);
            if (!string.IsNullOrWhiteSpace(sessionKey)) VerifiedSessions.TryAdd(sessionKey, 0);
            return true;
        }

        if (!string.IsNullOrWhiteSpace(fingerprint) && RejectedFingerprints.TryGetValue(fingerprint, out rejectionReason))
        {
            ClientModGate.RejectSession(sessionId, rejectionReason);
            return false;
        }

        var pendingKey = CreatePendingKey(sessionKey, fingerprint);
        if (string.IsNullOrWhiteSpace(pendingKey)) return true;

        var now = DateTimeOffset.UtcNow;
        var pending = PendingClients.GetOrAdd(
            pendingKey,
            key => new PendingChallenge(key, sessionKey, fingerprint, FirstSeenUtc: now, Challenge: null, IssuedAtUtc: null));

        if (now - pending.FirstSeenUtc <= TimeSpan.FromSeconds(_settings.ChallengeTimeoutSeconds)) return true;

        rejectionReason = $"未在 {_settings.ChallengeTimeoutSeconds} 秒内完成反作弊客户端握手，请确认已安装配套 BepInEx 插件。";
        RejectClient(sessionId, fingerprint, rejectionReason);
        return false;
    }

    private static async Task IssueChallengeAsync(MongoId sessionId, HttpContext context)
    {
        var settings = _settings ?? new AntiCheatSettings();
        var sessionKey = ResolveSessionKey(sessionId);
        var fingerprint = ResolveClientFingerprint(context);
        var now = DateTimeOffset.UtcNow;
        var challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(ChallengeBytes)).ToLowerInvariant();

        foreach (var pendingKey in EnumeratePendingKeys(sessionKey, fingerprint))
        {
            PendingClients[pendingKey] = new PendingChallenge(
                pendingKey,
                sessionKey,
                fingerprint,
                FirstSeenUtc: now,
                Challenge: challenge,
                IssuedAtUtc: now);
        }

        _logger?.Info($"[AntiCheat] Issued handshake challenge for {DescribeClient(sessionKey, fingerprint)}.");

        await WriteJsonAsync(
            context,
            StatusCodes.Status200OK,
            new ChallengeResponse(true, null, challenge, now.AddSeconds(settings.ChallengeTimeoutSeconds), settings.ChallengeTimeoutSeconds));
    }

    private static async Task VerifyResponseAsync(MongoId sessionId, HttpContext context)
    {
        var sessionKey = ResolveSessionKey(sessionId);
        var fingerprint = ResolveClientFingerprint(context);

        try
        {
            var request = await JsonSerializer.DeserializeAsync<HandshakeVerifyRequest>(context.Request.Body, JsonOptions);
            if (request is null)
            {
                await RejectVerifyAsync(sessionId, context, fingerprint, "反作弊握手请求体为空。");
                return;
            }

            if (!TryValidateResponse(request, sessionKey, fingerprint, out var normalizedMods, out var rejectionReason))
            {
                await RejectVerifyAsync(sessionId, context, fingerprint, rejectionReason);
                return;
            }

            if (!string.IsNullOrWhiteSpace(sessionKey)) VerifiedSessions.TryAdd(sessionKey, 0);
            if (!string.IsNullOrWhiteSpace(fingerprint)) VerifiedFingerprints.TryAdd(fingerprint, 0);
            if (!string.IsNullOrWhiteSpace(fingerprint)) RejectedFingerprints.TryRemove(fingerprint, out _);
            RemovePending(sessionKey, fingerprint);
            ClientModGate.MarkHandshakeVerified(sessionId);

            _logger?.Info(
                $"[AntiCheat] Handshake verified for {DescribeClient(sessionKey, fingerprint)}. Client mods: {string.Join(", ", normalizedMods)}");

            await WriteJsonAsync(context, StatusCodes.Status200OK, new VerifyResponse(true, null));
        }
        catch (JsonException)
        {
            await RejectVerifyAsync(sessionId, context, fingerprint, "反作弊握手 JSON 格式无效。");
        }
    }

    private static bool TryValidateResponse(
        HandshakeVerifyRequest request,
        string sessionKey,
        string fingerprint,
        out string[] normalizedMods,
        out string rejectionReason)
    {
        normalizedMods = NormalizeModList(request.Mods);
        rejectionReason = string.Empty;
        var settings = _settings ?? new AntiCheatSettings();

        var pending = FindPending(sessionKey, fingerprint, request.Challenge);
        if (pending is null || string.IsNullOrWhiteSpace(pending.Challenge))
        {
            rejectionReason = "服务端没有找到对应的反作弊挑战码。";
            return false;
        }

        if (!string.Equals(pending.Challenge, request.Challenge, StringComparison.Ordinal))
        {
            rejectionReason = "反作弊挑战码不匹配。";
            return false;
        }

        if (pending.IssuedAtUtc is null
            || DateTimeOffset.UtcNow - pending.IssuedAtUtc.Value > TimeSpan.FromSeconds(settings.ChallengeTimeoutSeconds))
        {
            rejectionReason = "反作弊挑战码已超时。";
            return false;
        }

        var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(nowUnix - request.Timestamp) > settings.TimestampToleranceSeconds)
        {
            rejectionReason = "反作弊握手时间戳超出允许范围。";
            return false;
        }

        if (!IsHmacValid(request, normalizedMods, settings.SharedSecret))
        {
            rejectionReason = "反作弊握手指纹校验失败。";
            return false;
        }

        var loaded = normalizedMods.ToHashSet(StringComparer.OrdinalIgnoreCase);

        var missing = settings.RequiredMods.Where(required => !loaded.Contains(required)).ToArray();
        if (missing.Length > 0)
        {
            rejectionReason = $"缺少必需客户端 Mod：{string.Join(", ", missing)}";
            return false;
        }

        var banned = settings.BannedMods.Where(loaded.Contains).ToArray();
        if (banned.Length > 0)
        {
            rejectionReason = $"检测到禁止加载的客户端 Mod：{string.Join(", ", banned)}";
            return false;
        }

        var allowed = settings.AllowedMods.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var disallowed = normalizedMods.Where(mod => !allowed.Contains(mod)).ToArray();
        if (disallowed.Length > 0)
        {
            rejectionReason = $"检测到未加入允许列表的客户端 Mod：{string.Join(", ", disallowed)}";
            return false;
        }

        return true;
    }

    private static async Task RejectVerifyAsync(MongoId sessionId, HttpContext context, string fingerprint, string reason)
    {
        RejectClient(sessionId, fingerprint, reason);
        await WriteJsonAsync(context, StatusCodes.Status403Forbidden, new VerifyResponse(false, reason));
    }

    private static void RejectClient(MongoId sessionId, string fingerprint, string reason)
    {
        if (!string.IsNullOrWhiteSpace(fingerprint)) RejectedFingerprints[fingerprint] = reason;
        ClientModGate.RejectSession(sessionId, reason);
    }

    private static bool IsVerified(string sessionKey, string fingerprint)
    {
        return (!string.IsNullOrWhiteSpace(sessionKey) && VerifiedSessions.ContainsKey(sessionKey))
            || (!string.IsNullOrWhiteSpace(fingerprint) && VerifiedFingerprints.ContainsKey(fingerprint));
    }

    private static PendingChallenge? FindPending(string sessionKey, string fingerprint, string? challenge)
    {
        foreach (var key in EnumeratePendingKeys(sessionKey, fingerprint))
        {
            if (!PendingClients.TryGetValue(key, out var pending)) continue;
            if (string.IsNullOrWhiteSpace(challenge) || string.Equals(pending.Challenge, challenge, StringComparison.Ordinal))
                return pending;
        }

        return null;
    }

    private static void RemovePending(string sessionKey, string fingerprint)
    {
        foreach (var key in EnumeratePendingKeys(sessionKey, fingerprint))
            PendingClients.TryRemove(key, out _);
    }

    private static IEnumerable<string> EnumeratePendingKeys(string sessionKey, string fingerprint)
    {
        if (!string.IsNullOrWhiteSpace(sessionKey)) yield return $"session:{sessionKey}";
        if (!string.IsNullOrWhiteSpace(fingerprint)) yield return $"fingerprint:{fingerprint}";
    }

    private static string CreatePendingKey(string sessionKey, string fingerprint)
    {
        return !string.IsNullOrWhiteSpace(sessionKey)
            ? $"session:{sessionKey}"
            : string.IsNullOrWhiteSpace(fingerprint)
                ? string.Empty
                : $"fingerprint:{fingerprint}";
    }

    private static bool IsHmacValid(HandshakeVerifyRequest request, string[] normalizedMods, string secret)
    {
        if (string.IsNullOrWhiteSpace(request.Challenge) || string.IsNullOrWhiteSpace(request.Hmac)) return false;

        var payload = BuildHmacPayload(request.Challenge, request.Timestamp, normalizedMods);
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var expected = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
        var actual = request.Hmac.Trim().ToLowerInvariant();

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(actual));
    }

    private static string BuildHmacPayload(string challenge, long timestamp, IEnumerable<string> normalizedMods)
    {
        return challenge
            + "\n"
            + timestamp.ToString(CultureInfo.InvariantCulture)
            + "\n"
            + string.Join("\n", normalizedMods);
    }

    private static string[] NormalizeModList(IEnumerable<string>? mods)
    {
        return mods?
            .Where(mod => !string.IsNullOrWhiteSpace(mod))
            .Select(mod => mod.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray()
            ?? [];
    }

    private static string ResolveSessionKey(MongoId sessionId)
    {
        var value = sessionId.ToString();
        return string.IsNullOrWhiteSpace(value) ? string.Empty : value;
    }

    private static string ResolveClientFingerprint(HttpContext context)
    {
        // 反向代理部署时优先使用 X-Forwarded-For 的第一个 IP；没有代理时使用 Kestrel 看到的远端 IP。
        var forwardedFor = ReadHeader(context, "X-Forwarded-For")?.Split(',').FirstOrDefault()?.Trim();
        var ip = string.IsNullOrWhiteSpace(forwardedFor)
            ? context.Connection.RemoteIpAddress?.ToString()
            : forwardedFor;

        return string.IsNullOrWhiteSpace(ip) ? string.Empty : ip.Trim();
    }

    private static string DescribeClient(string sessionKey, string fingerprint)
    {
        if (!string.IsNullOrWhiteSpace(sessionKey)) return $"session {sessionKey}";
        if (!string.IsNullOrWhiteSpace(fingerprint)) return $"ip {fingerprint}";
        return "unknown client";
    }

    private static string? ReadHeader(HttpContext context, string name)
    {
        return context.Request.Headers.TryGetValue(name, out var value) ? value.ToString() : null;
    }

    private static async Task WriteJsonAsync(HttpContext context, int statusCode, object body)
    {
        if (context.Response.HasStarted) return;

        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";

        await context.Response.WriteAsync(JsonSerializer.Serialize(body, JsonOptions));
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private sealed record PendingChallenge(
        string Key,
        string SessionKey,
        string Fingerprint,
        DateTimeOffset FirstSeenUtc,
        string? Challenge,
        DateTimeOffset? IssuedAtUtc);

    private sealed record HandshakeVerifyRequest(string? Challenge, long Timestamp, string? Hmac, string[]? Mods);

    private sealed record ChallengeResponse(bool Success, string? Reason, string Challenge, DateTimeOffset ExpiresAtUtc, int TimeoutSeconds);

    private sealed record VerifyResponse(bool Success, string? Reason);
}
