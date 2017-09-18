# 编译说明

## libcutil 编译

### 依赖安装

```
sudo dnf install libuuid-devel jansson-devel
```

### linux

- `cd libcutil`
- `mkdir .build`
- `cd .build`
- `cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=~/usr/local` or `CXX=g++ cmake .. -DCMAKE_BUILD_TYPE=Debug`
- `make`

*note: g++ version in my case that is 5.1*
*install:if given a -DCMAKE_INSTALL_PREFIX . cmake will be install with this prefix (eg. cmake .. -DCMAKE_INSTALL_PREFIX=/home/seanchann/usr)*
