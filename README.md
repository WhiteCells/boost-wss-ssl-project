```sh
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=127.0.0.1"
```

```sh
mkdir build && cd build
cmake ..
make
./server
```