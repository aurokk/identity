# Identity

## Build
```
docker build -t identity .
docker run -d --name identity -p20010:80 identity
docker compose up -d
docker compose down -v
```