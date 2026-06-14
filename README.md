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

默认 `balanced` 配置会限制每个出口国家最多 50 个节点，避免单个国家占满结果。非偏好国家会写入：

```text
public/bestcf_other_regions.csv
```
