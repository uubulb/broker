|Type|Info|
|-|------|
|1|Nezha data structure (Protobuf)|
|2|Nezha data structure (JSON)|

## Examples
### Nezha data structure
#### Protobuf (definition)
```proto
syntax = "proto3";

message Host {
    string platform = 1;
    string platform_version = 2;
    repeated string cpu = 3;
    uint64 mem_total = 4;
    uint64 disk_total = 5;
    uint64 swap_total = 6;
    string arch = 7;
    string virtualization = 8;
    uint64 boot_time = 9;
    string ip = 10;
    string country_code = 11; // deprecated
    string version = 12;
    repeated string gpu = 13;
}

message State {
    double cpu = 1;
    uint64 mem_used = 3;
    uint64 swap_used = 4;
    uint64 disk_used = 5;
    uint64 net_in_transfer = 6;
    uint64 net_out_transfer = 7;
    uint64 net_in_speed = 8;
    uint64 net_out_speed = 9;
    uint64 uptime = 10;
    double load1 = 11;
    double load5 = 12;
    double load15 = 13;
    uint64 tcp_conn_count = 14;
    uint64 udp_conn_count = 15;
    uint64 process_count = 16;
    repeated State_SensorTemperature temperatures = 17;
    double gpu = 18;
}

message Data {
    Host host = 1;
    State state = 2;
}
```

#### JSON
```json
{
  "host": {
    "platform": "chimera",
    "platform_version": "2024",
    "cpu": [
      "Cortex-A53 4 Physical Core",
      "Cortex-A72 2 Physical Core"
    ],
    "mem_total": 8589934592,
    "disk_total": 256000000000,
    "swap_total": 4194304000,
    "arch": "aarch64",
    "boot_time": 1719300000,
    "ip": "1.1.1.1",
    "country_code": "",
    "version": "1.0",
    "gpu": [
        "3dfx Voodoo3 2000 AGP",
        "PowerVR GE8320"
    ]
  },
  "state": {
    "cpu": 0.4324675324675325,
    "mem_used": 6300000000,
    "disk_used": 50500000000,
    "swap_used": 102400000,
    "net_in_transfer": 8123456789,
    "net_out_transfer": 3456789012,
    "net_in_speed": 1720,
    "net_out_speed": 840,
    "uptime": 3950000,
    "load1": 0.05,
    "load5": 0.12,
    "load15": 0.18,
    "tcp_conn_count": 35,
    "udp_conn_count": 18,
    "process_count": 1620,
    "temperatures": [
        {
            "name": "soc_thermal",
            "temperature": "36.4364"
        }
    ],
    "gpu": 0
  }
}
```
