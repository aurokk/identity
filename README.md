# Identity

## Build

```
docker build -t identity .
docker run -d --name identity -p20010:80 identity
docker compose up -d --build
docker compose down -v
```

## Migrations

```
dotnet new tool-manifest
dotnet tool install dotnet-ef
dotnet tool restore
```

```
dotnet ef migrations add Initial \
-o Migrations/Identity \
--context ApplicationDbContext \
--project src/Migrations \
--startup-project src/Api
```

## HTTPS Kestrel

```
dotnet dev-certs https -ep /Users/dk/.aspnet/https/localhost.pfx -p localhost
dotnet dev-certs https --trust
dotnet dev-certs https --clean
```

## Environment

```
docker compose run --service-ports -d identity-db
```