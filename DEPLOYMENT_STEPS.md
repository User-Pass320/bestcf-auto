# SelfDeploy 部署步骤

## 1. 路径和边界

状态化 SelfDeploy：

```text
C:\Users\sundewang\edgetunnel-bestcf-selfdeploy
```

保留的另一条技术路径：

```text
C:\Users\sundewang\bestcf-auto
```

两个项目不共用数据库和工作目录。

## 2. 一次性迁移和基线复测

迁移现有候选、复验结果和正式订阅后，使用 CN 直连网络执行：

```powershell
& 'C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\update-bestcf-and-deploy.ps1' `
  -RunMode Prebuild `
  -ExpectedInterfaceIndex 19
```

该模式只建立 SQLite 观测基线，不部署 Pages，不替换线上订阅。

主要产物：

```text
bestcf_work\bestcf_observations.sqlite
bestcf_work\prebuild_nonhk_candidates.csv
bestcf_work\prebuild_nonhk_audit.csv
bestcf_work\stateful_run_summary.json
```

## 3. 影子验证

Wednesday 逻辑：

```powershell
& 'C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\update-bestcf-and-deploy.ps1' `
  -RunMode Shadow `
  -EffectiveMode Wednesday `
  -ExpectedInterfaceIndex 19
```

Sunday 逻辑：

```powershell
& 'C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\update-bestcf-and-deploy.ps1' `
  -RunMode Shadow `
  -EffectiveMode Sunday `
  -ExpectedInterfaceIndex 19
```

影子模式积累独立严格确认次数，但不生成正式发布事务。

## 4. 正式发布

```powershell
& 'C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\update-bestcf-and-deploy.ps1' `
  -RunMode Manual `
  -EffectiveMode Sunday `
  -ExpectedInterfaceIndex 19
```

发布顺序固定为：

```text
生成 staging
  -> 校验节点数和地区数
  -> Wrangler 部署 Pages
  -> 下载线上 bestcf_final.txt
  -> 在线 SHA-256 与 staging 一致
  -> finalize-publish.py 提交 SQLite published 状态
  -> 原子替换本地 public\bestcf_final.txt
```

部署或在线校验失败时，不提交 SQLite 发布状态，也不替换本地正式文件。

## 5. 定时任务

```powershell
cd C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\bestcf-auto
.\scripts\register-selfdeploy-tasks.ps1 -ExpectedInterfaceIndex 19
```

预期任务：

```text
BestCF SelfDeploy Wednesday：周三 03:00
BestCF SelfDeploy Sunday：周日 03:00
BestCF Auto Update：周日 04:00，继续指向 C:\Users\sundewang\bestcf-auto
```

旧的每 6 小时 `BestCF Auto SelfDeploy Update` 保持禁用。

## 6. 验收

```powershell
python -m unittest discover -s .\tests -v
python .\bestcf_tool.py validate-output .\public\bestcf_final.txt --min-lines 10 --min-regions 3
Get-ScheduledTask | Where-Object TaskName -like '*BestCF*'
Get-FileHash .\public\bestcf_final.txt -Algorithm SHA256
```

在线文件：

```text
https://bestcf-auto-stitchb9283.pages.dev/bestcf_final.txt
```
