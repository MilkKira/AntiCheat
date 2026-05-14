using SPTarkov.Server.Core.Models.Spt.Mod;
using Range = SemanticVersioning.Range;
using Version = SemanticVersioning.Version;

namespace Milkkira.AntiCheat.Server;

// SPT 服务端模组元数据。SPT 会读取这些字段来展示模组信息、判断版本范围和依赖关系。
// 这里不参与反作弊逻辑本身，但 ModGuid 应尽量和 AntiCheatConstants.ServerGuid 保持一致，方便排查。
public sealed record AntiCheatMetaData : AbstractModMetadata
{
    public override string ModGuid { get; init; } = "com.milkkira.anticheat.server";
    public override string Name { get; init; } = "MAC";
    public override string Author { get; init; } = "Milkkira";
    public override List<string>? Contributors { get; init; } = [];
    public override Version Version { get; init; } = new("1.0.0");
    public override Range SptVersion { get; init; } = new("~4.0.0");
    public override List<string>? Incompatibilities { get; init; } = [];
    public override Dictionary<string, Range>? ModDependencies { get; init; } = [];
    public override string? Url { get; init; } = "https://github.com/";
    public override bool? IsBundleMod { get; init; } = false;
    public override string License { get; init; } = "MIT";
}
