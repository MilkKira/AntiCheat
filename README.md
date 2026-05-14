# TarkovBeta AntiCheat

This folder contains two companion assemblies:

- `TarkovBeta.AntiCheat.Server.dll`: SPT server mod for `SPT/user/mods`.
- `TarkovBeta.AntiCheat.Client.dll`: BepInEx plugin for `BepInEx/plugins`.

The server checks the client mod list reported to `/singleplayer/clientmods` and rejects sessions that do not include both:

- `com.fika.core`
- `com.tarkovbeta.anticheat.client`

Rejected sessions receive a normal SPT error response and their notifier websocket URL is poisoned/closed if they try to continue. This intentionally disconnects the client instead of forcing a crash.

## Build

```powershell
dotnet build .\AntiCheat\AntiCheat.sln -c Release
```

## Install

Copy the built DLLs:

```text
AntiCheat/dist/server/TarkovBeta.AntiCheat.Server.dll
  -> SPT/user/mods/TarkovBeta.AntiCheat/TarkovBeta.AntiCheat.Server.dll

AntiCheat/dist/client/TarkovBeta.AntiCheat.Client.dll
  -> BepInEx/plugins/TarkovBeta.AntiCheat/TarkovBeta.AntiCheat.Client.dll
```
