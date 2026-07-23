# BestCF Auto

自动生成给 edgetunnel 使用的优选源文件。

## 数据链路

```text
本机 SelfDeploy 定时任务运行状态化更新
  -> 生成 public/bestcf_final.txt
  -> Cloudflare Pages 或 GitHub Pages 托管 bestcf_final.txt
  -> edgetunnel 后台“自定义优选地址”填写该 URL
  -> Clash 使用 edgetunnel 生成的 /sub?token=... 订阅
```

`bestcf_final.txt` 不是 Clash 直接订阅文件；它是 edgetunnel 的优选源输入。

## SelfDeploy 状态化链路

`C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\update-bestcf-and-deploy.ps1` 使用本机 CN 直连环境执行：

```text
CN 直连硬预检
  -> SQLite 按状态和 next_test_at 选择到期候选
  -> YouTube/Ping0 严格双主判；VN 归一化为 HK
  -> 地区一致后再执行分层延迟测试
  -> active 三次延迟；轮换池一次延迟；发布前补齐三次
  -> HK:20、DE:20、其他国家:30；同 host 按 1/2/6 软填充
  -> 同真实出口 IP 最多 3 条
  -> staging 部署 Cloudflare Pages
  -> 在线 SHA-256 一致后提交 SQLite 发布状态
```

源文件下载可以使用系统代理；`CFST` 和候选 Mihomo 进程会清除代理环境变量。预检要求：

- Cloudflare Trace `loc=CN`；
- IPv4 默认路由使用指定物理网卡；
- 没有活动的 TUN/TAP/Wintun/VPN/Clash/Mihomo 等虚拟代理网卡。

现有 CSV、最终复验和正式订阅会迁移进 SQLite。冻结快照导入 8,677 条候选，其中 852 条进入一次性非 HK 基线复测。基线和影子运行不覆盖当前线上订阅。

首次基线复测：

```powershell
& 'C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\update-bestcf-and-deploy.ps1' `
  -RunMode Prebuild `
  -ExpectedInterfaceIndex 19
```

影子运行：

```powershell
& 'C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\update-bestcf-and-deploy.ps1' `
  -RunMode Shadow `
  -EffectiveMode Wednesday `
  -ExpectedInterfaceIndex 19
```

常规手动运行但只生成 staging、不部署：

```powershell
& 'C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\update-bestcf-and-deploy.ps1' `
  -RunMode Manual `
  -EffectiveMode Sunday `
  -ExpectedInterfaceIndex 19 `
  -SkipCfst `
  -SkipDeploy
```

常规调度参数：

```text
周三 03:00：全部正式非 HK、到期候补和轮换分片；不运行 CFST
周日 03:00：同上，并低频复测 HK、运行两个 CFST 端口
CFST 三周轮换：443/2053 -> 2083/2087 -> 2096/8443
每轮软上限 600、硬上限 800
```

增量来源包括 `bestcf.pages.dev` 已发现列表、`free-nodes/clashfree`、`free-nodes/v2rayfree` 和 `chengaopan/AutoMergePublicNodes`。第三方地区标签只用于候选调度，发布地区必须由 YouTube/Ping0 本轮严格结果决定。

`C:\Users\sundewang\bestcf-auto` 是保留的另一条技术路径，其 `BestCF Auto Update` 任务继续在周日 04:00 运行。

## 私密模板

真实模板文件 `template.yaml` 被 `.gitignore` 排除，不提交到公开仓库。

GitHub Actions 通过仓库 Secret 注入模板：

```text
Secret name: TEMPLATE_YAML_B64
Secret value: template.yaml 的 Base64 内容
```

本地生成 Base64 的 PowerShell 命令：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\bestcf-auto\template.yaml"))
```

GitHub 设置路径：

```text
GitHub 仓库
Settings
Secrets and variables
Actions
New repository secret
```

## 本地验证

```powershell
cd C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\bestcf-auto
python -m py_compile bestcf_tool.py geo_policy.py state_store.py scheduler.py
python -m unittest discover -s .\tests -v
```

快速功能验证：

```powershell
python bestcf_tool.py `
  --profile balanced `
  --workdir ./bestcf_work `
  --template ./template.yaml `
  --mihomo "E:\v2rayN-windows-64\bin\mihomo\mihomo.exe" `
  --limit 20 `
  --latency-pool-limit 20 `
  --geo-initial-limit 20 `
  --geo-refill-max-tested 20 `
  --speed-limit 0 `
  --time-budget 120 `
  --time-safety-margin 20 `
  --output ./public/bestcf_final.txt
```

## 发布后接入 edgetunnel

Cloudflare Pages 或 GitHub Pages 发布后，拿到：

```text
https://你的域名/bestcf_final.txt
```

填入 edgetunnel 后台：

```text
优选订阅生成
自定义优选地址
```

Clash / Clash Verge 使用 edgetunnel 输出的订阅：

```text
https://test1-45b.pages.dev/sub?token=...
```

## SelfDeploy 定时任务

注册周三、周日任务：

```powershell
cd C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\bestcf-auto
.\scripts\register-selfdeploy-tasks.ps1
```

注册结果：

```text
BestCF SelfDeploy Wednesday：周三 03:00
BestCF SelfDeploy Sunday：周日 03:00
BestCF Auto Update：周日 04:00，保持原项目路径不变
```

`.github/workflows/update.yml` 只保留手动 `workflow_dispatch`，不作为 SelfDeploy 的定时发布链路。

