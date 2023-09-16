# Power

Power это сервис для управления пользователями,
в том числе логина, регистрации, удаления и прочего.

Построено на [AspNetCore Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-7.0&tabs=visual-studio).

Стек: C#, .NET7, PostgreSQL.

## Dependencies

1. `dotnet sdk >= 7.0.400`
2. `postgreSQL`
3. `docker & docker compose`

## Build & Run

Для запуска проекта есть набор сконфигурированных заранее сервисов, нужно
просто запустить.

Можно запустить одной командой, с помощью докера:
`docker compose up -d --build power`. Образы будут собраны из исходников и запущены.

Либо можно запустить из исходников локально:

1. Запустить базу данных: `docker compose up -d power-db`.
1. Запустить мигратор: `Api/Properties/launchSettings.json` конфигурацию `Migrator`.
1. Запустить апи: `Api/Properties/launchSettings.json` конфигурацию `Api`.

Остановить и удалить любые сервисы запущенные в докере:
`docker compose down -v`.

## Migrations

В проекте используется Entity Framework, все миграции генерируются и применяются с его помощью.

Для работы с миграциями локально нужно выполнить команду `dotnet tool restore`.

В проекте есть контекст для работы с базой данных:

1. `ApplicationDbContext` — контекст для работы с ресурсами, скоупами, клиентами и тд.

Чтобы создать миграцию в `ApplicationDbContext`:

```
dotnet ef migrations add Initial \
-o Migrations/Identity \
--context ApplicationDbContext \
--project src/Migrations \
--startup-project src/Api
```

## Contributing

Изменения в проекте приветствуются в соответствии с [правилами](https://github.com/yaiam/.github/blob/main/CONTRIBUTING.md).