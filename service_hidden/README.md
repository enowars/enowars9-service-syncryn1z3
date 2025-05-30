Hidden mechanics
====================
A custom glibc is compiled to inject an insecure version of strncmp().

# Build the image
```
docker build . -t microdebian/bookworm
```
