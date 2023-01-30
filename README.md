# oAuth2 server

## Run environment

Install __uuid__ extension for postgres
```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

## Run tests

```bash
go test -v ./test
```