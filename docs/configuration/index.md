## 结构

```yaml
server: null

# agent fields
ip_query: false
debug: false
use_ipv6_countrycode: false
dns: []
listen_addr: 10.0.0.12:8088
```

## 字段

#### **server**
[服务器配置](server.md)。

#### **ip_query**
启用 IP 查询，从 Cloudflare 获取 IP 并上报。如禁用则使用数据源提供的 IP。

#### **use_ipv6_countrycode**
优先使用 IPv6 地址查询地区码。

#### **dns**
自定义 DNS 服务器列表。如不指定，使用内置 DNS 列表。

#### **listen_addr**
指定 TCP 服务器监听地址。