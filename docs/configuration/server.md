## 结构
```yaml
server: 
  example:
    source: http://10.0.0.1:36436
    source_type: 1
    auth: false
    auth_header: Authorization
    auth_password: Bearer test
    fetch_interval: 10
    date_type: 1
    version_suffix: -broker
    remote: example.com:443
    password: good_password
    tls: false
    insecure: false
    report_delay: 1
    ssh:
      enabled: false
      host: 10.0.0.1:22
      user: root
      use_key: false
      password: very_secure
      key: ~/.ssh/id_rsa
```

## 字段

#### **source**
数据源地址，可为 HTTP/HTTPS。不支持 HTTP/3。

#### **source_type**
数据源类型。1 为 HTTP，2 为 TCP。

#### **auth**
启用 HTTP 认证，目前只支持通过请求头完成认证。

#### **auth_header**
指定验证请求头。

#### **auth_password**
请求头的内容，即密码。

#### **fetch_interval**
必填，指定每一次数据获取的间隔（秒）。

#### **data_type**
必填，[数据类型](type.md)。

#### **version_suffix**
指定版本后缀，默认为 `-broker`。

#### **remote**
哪吒 Dashboard gRPC 地址。

#### **password**
Dashboard 认证密码。

#### **tls**
为 gRPC 连接启用 TLS。

#### **insecure**
禁用证书检查。

#### **report_delay**
上报间隔，范围 1~3 秒。

### SSH
#### **enabled**
启用 SSH 连接，如不启用，Web 终端和命令执行功能将不可用。

#### **host**
远程 SSH 主机地址。

#### **user**
主机用户名。

#### **use_key**
使用密钥验证。启用后，不再进行密码认证。

#### **password**
主机用户密码。

#### **key**
私钥路径，可使用 `~` 代替默认家目录。