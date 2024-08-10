## Structure

```yaml
server: null

# agent fields
ip_query: false
debug: false
use_ipv6_countrycode: false
dns: []
listen_addr: 10.0.0.12:8088
```

## Fields

#### **server**
[Server configurations](server.en.md).

#### **ip_query**
Enables IP querying. Retrieves the IP address from Cloudflare and reports it to the Dashboard.

If disabled, the IP address will be obtained from the data source.

#### **use_ipv6_countrycode**
Prefers using the IPv6 address for country code lookup.

#### **dns**
Specifies a custom list of DNS servers. If not provided, the built-in default list will be used.

#### **dns**
Specifies the address of the TCP server listens to.