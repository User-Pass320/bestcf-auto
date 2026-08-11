# BestCF Auto

自动生成给 edgetunnel 使用的优选源文件。

## 数据链路

```text
Windows 周任务或手动 GitHub Actions 运行 bestcf_tool.py
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

`.github/workflows/update.yml` 提供手动云端更新；如果生成结果未通过真实出口复验和 `bestcf_tool.py validate-output` 校验，workflow 会保留现有 `public/` 文件，不覆盖有效结果。

稳定更新建议使用本机 Windows 定时任务：

```powershell
cd C:\Users\sundewang\bestcf-auto
.\scripts\register-windows-task.ps1
```

本机任务每周日 04:00 运行，作为更贴近本地网络质量的主更新路径：

```text
scripts/update-local-and-push.ps1
```

它会本地生成新的 `public/bestcf_final.txt`，校验至少 30 行、3 个地区，然后提交并推送到 GitHub。Cloudflare Pages 会自动重新部署 `public/`。

本机主路径依次扫描 CFST 的 `443/2053/2083/2087/2096/8443` 六个端口，并复用增量历史池。每轮还会用最多约 240 秒刷新 `bestcf.pages.dev` 首页发现源及内置第三方源；刷新失败不会阻断 CFST/历史池发布。两个候选池按 `host+port` 去重合并后，再统一执行无缓存的 YouTube/Ping0 双主判。

最终发布要求 YouTube 与 Ping0 都返回地区；`VN` 先归一为 `HK`。两者一致时直接采用共同结果，两者不一致时统一采用 Ping0 的归一化地区，任一服务 UNKNOWN 时仍淘汰。发布上限默认为每个地区 30 条，`HK` 和 `DE` 为 20 条。

```text
public/bestcf_external_sources.csv
public/bestcf_external_source_prune_candidates.csv
public/source_candidate_merge_summary.json
public/final_true_exit_verify_summary.json
```

以上报告分别记录外部源健康状态、建议裁剪源、候选合并数量和最终真实出口复验结果。当前 all-regions 本机更新会把超过地区上限的已探测候选写入：

```text
public/bestcf_other_regions.csv
```

