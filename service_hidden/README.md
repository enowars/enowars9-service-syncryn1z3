Hidden mechanics
====================
A custom library is compiled to inject an insecure version of strncmp().

# Build the library
```
make
```

# Run tests
```
LD_PRELOAD=../service/lib/libjson.so ./build/json_test
```
