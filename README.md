# 3X-UI Mihomo Subscription Transformer

将 3X-UI 输出的 Clash/Mihomo YAML 订阅转换为可直接使用的智能配置。它保留上游节点与 `Subscription-Userinfo` 流量头，同时注入 DNS、TUN、分流规则和自动选节点策略。

它是订阅侧车，不是代理核心：3X-UI/Xray 仍负责用户、节点和流量统计；Mihomo 客户端负责 DNS、规则和健康检查。

## 功能

- 多订阅路径可映射到不同上游订阅与策略。
- 节点名在每次拉取时动态读取，不依赖面板中的固定名称。
- `url-test`、`fallback` 和 `load-balance` 自动组策略。
- 节点名称正则筛选，便于按协议或地区构建订阅。
- 默认提供 TUN、Fake-IP、加密 DoH、国内直连和海外代理 DNS 策略。
- 透传 `Subscription-Userinfo`、`Profile-Update-Interval` 等 3X-UI 响应头。
- 仅接受环回地址上游，适合由 Nginx/Caddy 公开暴露订阅地址。

## 架构

```text
Mihomo client -> Nginx/Caddy -> transformer (127.0.0.1) -> 3X-UI (127.0.0.1)
                                  |                         |
                                  +-- DNS/rules/groups ------+
```

不要将转换器直接监听在公网；应由反向代理处理 TLS、访问日志和路径公开。订阅 URL 本身相当于凭据，泄露后应在 3X-UI 中撤销并重建。

## 安装

需要 Python 3.10+ 和 PyYAML：

```bash
python3 -m pip install -r requirements.txt
install -Dm755 xui_mihomo_subscription.py /usr/local/libexec/xui_mihomo_subscription.py
install -Dm600 config.example.json /etc/xui-mihomo-subscription.json
python3 /usr/local/libexec/xui_mihomo_subscription.py --config /etc/xui-mihomo-subscription.json
```

随后用 `systemd/xui-mihomo-subscription.service` 创建仅监听环回地址的服务。将示例中的 `REPLACE_*` 改成实际 3X-UI 路径；不要把真实配置提交到 Git。

## 配置

`config.example.json` 包含两个策略：

- `smart`: `url-test` 自动选择最低延迟节点，适合常规单用户订阅。
- `resilient`: `fallback` 优先使用第一个健康节点，适合强调故障切换的场景。

`paths` 的键是公开路径，值可为字符串（兼容旧格式）或对象。对象允许指定 `upstream_path` 和 `policy`。每个策略可设置：

- `node_include` / `node_exclude`: Python 正则，匹配节点名称。
- `group_type`: `url-test`、`fallback` 或 `load-balance`。
- `health_check`: URL、周期、超时、容差和失败阈值。
- `dns` / `tun` / `rules`: 覆盖默认的 Mihomo 块。

默认规则会让私有网络和中国大陆域名/IP 直连，其他流量走 `PROXY`。海外 DoH 请求显式通过 `PROXY`，避免本地网络看到明文海外 DNS 查询。应用自行使用 DoH/DoT 或 Android Private DNS 时，可能绕过 TUN 的 53 端口劫持。

## 验证

```bash
python3 -m unittest discover -s tests -v
curl -I http://127.0.0.1:18082/clash/example
```

## 安全边界

- 上游必须是 `127.0.0.1`、`localhost` 或 `::1` 的 HTTP 地址，防止被误配置成开放代理。
- 示例不包含服务器 IP、订阅令牌、面板账号、私钥或真实用户路径。
- 本项目不能阻止订阅地址被转发；访问控制、TLS 和撤销仍应由反向代理与 3X-UI 承担。

## 许可证

MIT
