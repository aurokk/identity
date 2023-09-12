FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /source

COPY *.sln                   .
COPY src/Api/*.csproj        ./src/Api/
COPY src/Identity/*.csproj   ./src/Identity/
COPY src/Migrations/*.csproj ./src/Migrations/
RUN dotnet restore

COPY src/Api/.        ./src/Api/
COPY src/Identity/.   ./src/Identity/
COPY src/Migrations/. ./src/Migrations/
WORKDIR /source/src/Api
RUN dotnet publish -c release -o /dist --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:7.0
COPY --from=build /dist/* /app/
WORKDIR /app
ENTRYPOINT ["dotnet", "Api.dll"]