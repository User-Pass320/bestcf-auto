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
