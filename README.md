# Team Console

独立的 Team 母号与账号管理台。React 19 + TypeScript + Ant Design 前端，Flask / Waitress 后端，SQLite 脱敏查询索引。

## 功能

- 账号三段式导入、批次查询、Free / Team 套餐筛选。
- 普通授权、Team 授权、持久化任务进度、额度查询。
- Sub2API JSON 和 2FA 三段式 TXT 导出。
- 多母号、成员与邀请管理、席位切换、移出 Team、批量操作。
- SOCKS / HTTP 代理池管理。

普通与 Team 授权共用最多 100 个执行槽位。Team 授权失败或返回非 Team 套餐时最多重试 6 次，包含首次共 7 次；成功或手动停止后不继续重试。账号列表不显示无数据的 Team 席位列，席位操作仍保留。

本仓库只包含代码和空白配置模板，不包含账号、母号、密码、2FA 密钥、Token、Cookie、代理凭据或历史任务。`core/`、`config/` 保留新系统依赖的共享模块，但新后台不开放旧注册、邮箱素材和支付页面，也不启动旧任务恢复。

## Docker 部署

需要 Docker Engine 和 Docker Compose。以下命令在仓库根目录执行：

```sh
cp .env.example .env
cp business.env.example business.env
cp team-console/.env.example .console.env
```

编辑 `.console.env`，将 `TEAM_CONSOLE_API_KEY` 设置为自己的长随机密钥；未配置时服务拒绝对外启动。按需编辑 `business.env` 的代理配置，也可以登录后在“网络代理”中设置。

```sh
mkdir -p data
sudo chown 10001:10001 data business.env .console.env
sudo chmod 700 data
sudo chmod 600 business.env .console.env
docker compose up -d --build
docker compose ps
```

访问 `http://服务器地址:5050/`，先输入访问密钥。服务使用非 root 用户、只读容器文件系统、带鉴权的健康检查；仅 `data/` 和临时目录可写。默认限制为 4 CPU、4 GiB 内存，允许的内存加交换空间总上限为 5 GiB。资源较少的主机可自行调整 `compose.yaml`。

持久化数据在仓库根目录 `data/`，重建容器不会清空。`business.env`、`.console.env` 和数据目录均被 Git 忽略，不应加入镜像或提交。

更新时先确认没有运行中的任务，再拉取代码并执行：

```sh
git pull --ff-only
docker compose up -d --build
```

不要删除 `data/`。不要运行多个后台进程或容器共同写入同一个数据目录。

## 本地开发

需要 Python 3.12+、Node.js 22+：

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp business.env.example .env
cp team-console/.env.example team-console/.env
# 编辑 team-console/.env，填写自己的 TEAM_CONSOLE_API_KEY。
cd team-console/frontend
npm ci
npm run build
cd ../..
.venv/bin/python team-console/server.py
```

本地默认访问 `http://127.0.0.1:5050/`，数据保存到 `team-console/data/store/`，不读取其他项目的数据。前端开发可在 `team-console/frontend` 执行 `npm run dev`。

## 离线验证

```sh
(cd team-console/frontend && npm ci && npm run build)
PYTHON_DOTENV_DISABLED=1 PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="$PWD/team-console" .venv/bin/python -m unittest discover -s team-console/tests -v
```

Python 测试使用临时数据与模拟业务调用；前端仅做 TypeScript / Vite 构建，不执行浏览器或 UI 测试。

更详细的模块说明见 [team-console/README.md](team-console/README.md)。

## 许可

MIT，见 [LICENSE](LICENSE)。共享模块沿用原项目的版权声明。
