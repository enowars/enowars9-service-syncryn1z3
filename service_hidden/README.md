Hidden mechanics
====================
A custom library is compiled to inject an insecure version of strncmp().

# Build the library
```
mkdir build
cd build
cmake ..
make
```

# Strip binary
This preserves the function names, but removes source file paths.
```
strip --strip-debug src/libjson.so
```
