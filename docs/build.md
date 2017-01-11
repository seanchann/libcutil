# 编译说明

## libcutil 编译

### linux

- `cd libcutil`
- `mkdir build.release`
- `cd build.release`
- `cmake .. -DCMAKE_BUILD_TYPE=Release` or `CXX=g++ cmake .. -DCMAKE_BUILD_TYPE=Debug`
- `make`

*note: g++ version in my case that is 5.1*
