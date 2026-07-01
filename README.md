# BestCF Auto

自动生成给 edgetunnel 使用的优选源文件。

## 数据链路

```text
GitHub Actions 定时运行 bestcf_tool.py
  -> 生成 public/bestcf_final.txt
  -> Cloudflare Pages 或 GitHub Pages 托管 bestcf_final.txt
  -> edgetunnel 后台“自定义优选地址”填写该 URL
  -> Clash 使用 edgetunnel 生成的 /sub?token=... 订阅
```

`bestcf_final.txt` 不是 Clash 直接订阅文件；它是 edgetunnel 的优选源输入。

## 私密模板

真实模板文件 `template.yaml` 被 `.gitignore` 排除，不提交到公开仓库。

GitHub Actions 通过仓库 Secret 注入模板：

```text
Secret name: TEMPLATE_YAML_B64
Secret value: template.yaml 的 Base64 内容
```

本地生成 Base64 的 PowerShell 命令：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\sundewang\bestcf-auto\template.yaml"))
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
cd C:\Users\sundewang\bestcf-auto
python -m py_compile bestcf_tool.py
python bestcf_tool.py --help
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

## 稳定定时更新

GitHub Actions 会按 `.github/workflows/update.yml` 每 6 小时尝试云端更新，也可手动触发；如果云端生成结果未通过 `bestcf_tool.py validate-output` 校验，workflow 会保留现有 `public/` 文件，不覆盖有效结果。

稳定更新建议使用本机 Windows 定时任务：

```powershell
cd C:\Users\sundewang\bestcf-auto
.\scripts\register-windows-task.ps1
```

本机任务每 6 小时运行，作为更贴近本地网络质量的主更新路径：

```text
scripts/update-local-and-push.ps1
```

它会本地生成新的 `public/bestcf_final.txt`，校验至少 10 行，然后提交并推送到 GitHub。Cloudflare Pages 会自动重新部署 `public/`。

本机更新默认禁用 `geo` 与 `geo hint` 缓存，并使用 `--geo-providers youtube,ping0,ipwhois --selection-mode all-regions --country-max 35 --max-final-candidates 0 --geo-concurrency 16`。它会对本轮真连接通过的候选同时执行 `https://www.youtube.com/`、`https://ip.ping0.cc/geo` 与 `https://ipwho.is/` 交叉验证；最终地区按 `YouTube GL > ping0 > ipwho.is` 优先级选择，不再按偏好国家提前过滤。只有探测服务明确给出出口地区的候选才参与最终选择，最终按真实出口地区分组，每个出口地区最多写入 35 个节点。

为减少大量无效香港出口探测，本机与 GitHub Actions 更新默认启用本轮运行时 HK suppression：

```text
--hk-suppression
--hk-suppress-strategy worker
--hk-probe-cap 105
--hk-suppress-bucket-scope prefix
--hk-suppress-ipv4-prefix 20
--hk-suppress-ipv6-prefix 40
--hk-suppress-min-samples 6
--hk-suppress-confidence 0.98
--hk-suppress-explore-rate 0.05
```

该策略只使用本轮 `youtube/ping0/ipwhois` 实测结果，不使用持久 geo 缓存或 geo hint 缓存；只压制已实测为高置信 HK 的 IP 前缀桶，未知前缀与已出现非 HK 的前缀不会被压制。旧 825 个 geo 候选池离线回放显示：`prefix /20-/40 + min_samples=6 + hk_probe_cap=105` 可跳过约 185 个 HK 探测，JP/SG/KR/TW 误伤为 0；`min_samples=4/5` 会误伤 JP，因此不采用。

未启用 `--selection-mode all-regions` 时，默认 `balanced` 配置会限制每个出口国家最多 50 个节点，避免单个国家占满结果。当前 all-regions 本机更新会把超过每地区 35 个上限的已探测候选写入：

```text
public/bestcf_other_regions.csv
```

