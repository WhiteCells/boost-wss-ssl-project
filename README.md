### Boost WSS

```sh
# 生成私钥
openssl genrsa -out server.key 2048

# 生成自签名证书（Common Name 请填 127.0.0.1 或 localhost）
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/C=CN/ST=Test/L=Test/O=Local/OU=Dev/CN=127.0.0.1"
```
