## Structure
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

## Fields

#### **source**
The URL of the data source, supporting HTTP/HTTPS. HTTP/3 is not supported.

#### **source_type**
Type of the data source. 1 for HTTP, 2 for TCP.

#### **auth**
Enables HTTP authentication via headers.

#### **auth_header**
Specify the name of the authorization header.

#### **auth_password**
The value of the authorization header (i.e., the password).

#### **fetch_interval**
Required. Specifies the interval between each fetch (in seconds).

#### **data_type**
Required. Specifies the [data type](type.en.md).

#### **version_suffix**
Specifies the suffix for the version field. Defaults to `-broker`.

#### **remote**
The gRPC address of the Nezha Dashboard.

#### **password**
The client secret for the Dashboard.

#### **tls**
Enables TLS for gRPC connections.

#### **insecure**
Disables certificate integrity checks.

#### **report_delay**
Specifies the report delay, ranging from 1 to 4 seconds.

### SSH
#### **enabled**
Enables SSH. If disabled, the web terminal and command tasks will be unavailable.

#### **host**
Address of the remote host.

#### **user**
Host username.

#### **use_key**
Enables key-based authentication. Disables password authentication when enabled.

#### **password**
User password.

#### **key**
The path to the private key file. The `~` symbol can be used to represent the home directory.