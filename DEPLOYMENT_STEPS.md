# 部署步骤

## 0. 当前本地状态

本地项目目录：

```text
C:\Users\sundewang\bestcf-auto
```

已准备：

```text
bestcf_tool.py
requirements.txt
template.example.yaml
public/index.html
public/bestcf_final.txt
.github/workflows/update.yml
```

未提交、不会上传：

```text
template.yaml
template.b64.txt
bestcf_work/
```

## 1. 修改 edgetunnel 管理密码

你之前公开过后台地址和密码，先改掉 `ADMIN`。

Cloudflare 路径：

```text
Workers & Pages
test1-45b
Settings
Environment variables
ADMIN
修改为新密码
Redeploy
```

验证：

```text
旧密码不能登录
新密码可以登录
```

## 2. 创建 GitHub 仓库

浏览器打开：

```text
https://github.com/new
```

建议配置：

```text
Owner: User-Pass320
Repository name: bestcf-auto
Visibility: Public
不要勾选 Add a README file
不要勾选 Add .gitignore
不要选择 License
```

创建后仓库地址应为：

```text
https://github.com/User-Pass320/bestcf-auto
```

## 3. 推送本地仓库

在 PowerShell 执行：

```powershell
cd C:\Users\sundewang\bestcf-auto
.\scripts\push-to-github.ps1
```

验证：

```text
GitHub 仓库能看到 bestcf_tool.py
GitHub 仓库能看到 .github/workflows/update.yml
GitHub 仓库看不到 template.yaml
GitHub 仓库看不到 template.b64.txt
```

## 4. 添加 GitHub Actions Secret

先复制 Secret 值：

```powershell
cd C:\Users\sundewang\bestcf-auto
.\scripts\copy-template-secret.ps1
```

GitHub 设置路径：

```text
User-Pass320/bestcf-auto
Settings
Secrets and variables
Actions
New repository secret
```

填写：

```text
Name: TEMPLATE_YAML_B64
Secret: 粘贴剪贴板内容
```

验证：

```text
Actions secrets 列表出现 TEMPLATE_YAML_B64
```

## 5. 手动运行 GitHub Actions

GitHub 路径：

```text
User-Pass320/bestcf-auto
Actions
Update BestCF
Run workflow
Branch: main
Run workflow
```

验证：

```text
工作流成功
public/bestcf_final.txt 被更新提交
```

如果失败，优先看这几个步骤：

```text
Restore private template
Download mihomo
Run BestCF
Commit generated files
```

## 6. 用 Cloudflare Pages 托管 public

Cloudflare 路径：

```text
Workers & Pages
Create application
Pages
Connect to Git
选择 User-Pass320/bestcf-auto
```

构建配置：

```text
Build command: 留空或 true
Build output directory: public
Root directory: 留空
```

部署完成后，记录地址：

```text
https://你的项目名.pages.dev/bestcf_final.txt
```

建议项目名：

```text
bestcf-auto
```

则地址类似：

```text
https://bestcf-auto.pages.dev/bestcf_final.txt
```

## 7. 接入 edgetunnel 后台

打开：

```text
https://test1-45b.pages.dev/admin
```

在：

```text
优选订阅生成
自定义优选地址
```

填入：

```text
https://bestcf-auto.pages.dev/bestcf_final.txt
```

保存。

## 8. Clash 使用方式

Clash / Clash Verge 使用 edgetunnel 生成的订阅链接：

```text
https://test1-45b.pages.dev/sub?token=你的token
```

不要直接把 `bestcf_final.txt` 当 Clash 订阅。
