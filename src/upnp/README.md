# upnp 协议封装

## upnpc

upnp 客户端，发起SSDP消息，返回设备列表

编译：

```
clang -W -Wall -Wextra -o upnp -Os upnp.c -I/home/seanchann/source/github/miniupnp/ ./libminiupnpc.a
```