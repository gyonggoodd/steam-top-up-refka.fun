### Сборка проекта

Команда для кросс-компиляции бинарного файла под Linux (Ubuntu, Debian и др.):

```bash
GOOS=linux GOARCH=amd64 go build -o <name> main.go
```
* `<name>` — замените на желаемое имя исполняемого файла (например, `refka-backend`).
