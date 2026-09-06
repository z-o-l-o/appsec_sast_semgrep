# Отчет по 5 выбранным срабатываниям semgrep

- Проект "AppSec course project - SAST Semgrep" 
- Курс: Защита приложений - AppSec Инженер
- @VladZolo 09/2026
- Учебный проект по работе с SAST Semgrep.


## Структыра анализа:

Для каждого выбранного срабатывания:
- зафиксировать:
    - краткое описание из Semgrep (message/severity),
    - файл и номер строки;
- показать соответствующий фрагмент кода;
- своими словами объяснить:
    - что здесь потенциально небезопасного;
    - опасно ли это в данном учебном коде;
    - чем такая конструкция может быть опасна в реальном приложении.


## 01. py-dangerous-subprocess-shell

1. краткое описание из Semgrep (message/severity): 
- id: py-dangerous-subprocess-shell
- message: "Опасный вызов subprocess с shell=True (команда оболочки)"
- severity: ERROR

2. файл и номер строки:
- app.py
- 33┆ subprocess.run(cmd, shell=True)

3. соответствующий фрагмент кода:
```python
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    cmd = f"ping -c 1 {host}"
    subprocess.run(cmd, shell=True)
    return "OK"
```

4. что здесь потенциально небезопасного:
- "host" приходит напрямую от пользователя через HTTP-параметр и вставляется в строку команды.
- "shell=True" означает, что строка передаётся оболочке ОС
- то есть пользовательский ввод включается в команду, которую будет интерпретировать shell (!)

5. опасно ли это в данном учебном коде:
- конструкция опасна, последствия зависят от учебного окружения
- если запущен локально, то последтвия минимальны

6. чем такая конструкция может быть опасна в реальном приложении: 
- последствия зависят от окружения и прав/пользователя под которым работает приложение
- потенциально: выполнение произвольных команд ОС, удаление файлов, запуску процессов, до полной компрометации сервера

7. как исправить:
- добавить проверку соответствия "host" формату ip
- заменить строки 32 и 33 на строку
```python
subprocess.run(["ping", "-c", "1", host])
```
- 


## 02. py-requests-no-verify

1. краткое описание из Semgrep (message/severity): 
- id: py-requests-no-verify
- message: "HTTP-запрос с verify=False (отключена проверка TLS-сертификата)"
- severity: WARNING

2. файл и номер строки:
- app.py
- 50┆ r = requests.get(url, verify=False)

3. соответствующий фрагмент кода:
```python
@app.route("/check")
def check():
    url = request.args.get("url", "https://example.com")
    r = requests.get(url, verify=False)
    return f"Status: {r.status_code}"
```

4. что здесь потенциально небезопасного:
- "url" контролируется пользователем и передаётся серверу в requests.get()
- Это потенциальный SSRF
- дополнительо здесь "verify=False" отключает проверку TLS-сертификата HTTPS-сервера

5. опасно ли это в данном учебном коде:
- конструкция опасна, последствия зависят от учебного окружения
- если запущен локально, то последтвия минимальны 

6. чем такая конструкция может быть опасна в реальном приложении: 
- "verify=False" - приложение может установить HTTPS-соединение с сервером, чей сертификат не прошёл обычную проверку доверия
- злоумышленник может используя SSRF cделать запросы через сервер туда, куда сам атакующий напрямую обратиться не может и иметь доступ к : внутренним HTTP-сервисам и API,административным интерфейсам, сервисам в приватной сети, 
локальным портам и тд

7. как исправить:
- Жёсткий список разрешённых адресов (allow-list)
- блокировка внутренних адресов
- ставим таймауты, ограничение размера ответа, запрещаем пользователю управлять критичными заголовками ( Host ,  Authorization )
- контроль редиректов 
- Логи и алерты на обращения к локальным IP


## 03. py-insecure-md5

1. краткое описание из Semgrep (message/severity): 
- message: "Использование hashlib.md5 для хеширования пароля или важных данных"
- severity: WARNING

2. файл и номер строки:
- usils.py
- 6┆ m = hashlib.md5()

3. соответствующий фрагмент кода:
```python
def calculate_md5(password):
    m = hashlib.md5()
    m.update(password.encode("utf-8"))
    return m.hexdigest()
```

4. что здесь потенциально небезопасного:
- MD5 давно считается непригодным для хранения паролей, злоумышленник быстро вскроет хеш при наличии
- к тому же в коде не используется salt

5. опасно ли это в данном учебном коде:
- не опасно, в учебном коде как раз можно понять почему это плохой пример

6. чем такая конструкция может быть опасна в реальном приложении: 
- при утечке хешей, хеши быстро перебираются/ломаются
- при отсутствии соли хеши одинаковых паролей одинаковые

7. как исправить:
- сменить алгоритм хеширования с быстрого на медленный, специально разработанный для паролей, с солью и регулируемой вычислительной стоимостью.


## 04. py-insecure-yaml-load

1. краткое описание из Semgrep (message/severity): 
- id: py-insecure-yaml-load
- message: "Небезопасный вызов yaml.load без безопасного Loader"
- severity: ERROR

2. файл и номер строки:
- usils.py
- 12┆ data = yaml.load(raw)

3. соответствующий фрагмент кода:
```python
def unsafe_yaml_load(raw):
    data = yaml.load(raw)
    return data
```

4. что здесь потенциально небезопасного:
- небезопасная десериализация YAML

5. опасно ли это в данном учебном коде:
- да, это небезопасный способ обработки входных данных.

6. чем такая конструкция может быть опасна в реальном приложении: 
- злоумышленник потенциально может добиться выполнения нежелательных действий на сервере в процессе десериализации:
- выполнение кода с правами процесса приложения
- чтение или изменение доступных процессу файлов
- доступ к переменным окружения и секретам
- компрометация приложения
- дальнейшее проникновение во внутреннюю инфраструктуру...

7. как исправить:
- заменить "yaml.load(raw)" на "yaml.safe_load(raw)"
- если возможно то перейти на простой JSON


## 05. python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute

1. краткое описание из Semgrep (message/severity): 
- id: python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute
- message: "User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection."
- severity: ERROR

2. файл и номер строки:
- app.py
-   17┆ user_id = request.args.get("id", "")
    18┆ conn = get_db()
    19┆ cur = conn.cursor()
    20┆ query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
    21┆ cur.execute(query)


3. соответствующий фрагмент кода:
```python
@app.route("/user")
def user():
    user_id = request.args.get("id", "")
    conn = get_db()
    cur = conn.cursor()
    query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    if not row:
        return "User not found"
    return f"User: {row[1]} ({row[2]})"
```

4. что здесь потенциально небезопасного:
- "user_id" приходит напрямую из HTTP-запроса и через f-string вставляется непосредственно в SQL
- Приложение фактически позволяет пользовательскому вводу влиять на структуру SQL-запроса (SQLi)

5. опасно ли это в данном учебном коде:
- конструкция опасна, последствия зависят от учебного окружения

6. чем такая конструкция может быть опасна в реальном приложении: 
- SQL-инъекция может позволить атакующему чтению данных, обходу ограничений приложения, изменению или удалению данных, раскрытию персональной информации
- в отдельных случаях выполнения кода

7. как исправить:
- Использовать параметризованный запрос
- заменить строки 20 и 21 на 
```python
query = "SELECT id, username, email FROM users WHERE id = ?"
cur.execute(query, (user_id,))
```
- и добавить проверку "user_id" что это целое число


## 06. python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

1. краткое описание из Semgrep (message/severity): 
- id: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
- message: "Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language."
- severity: ERROR

2. файл и номер строки:
- insecure_db.py
- 8┆ cur.execute(query)


3. соответствующий фрагмент кода:
```python
def search_user_by_name(name):
    conn = sqlite3.connect("example.db")
    cur = conn.cursor()
    query = "SELECT id, username FROM users WHERE username = '" + name + "'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows
```

4. что здесь потенциально небезопасного:
- "name" вставляется непосредственно внутрь SQL-запроса (конкатенация строк)
- Приложение фактически позволяет пользовательскому вводу влиять на структуру SQL-запроса (SQLi)

5. опасно ли это в данном учебном коде:
- конструкция опасна, последствия зависят от учебного окружения
- если используется для демонстрации SQLi, то ОК

6. чем такая конструкция может быть опасна в реальном приложении: 
- как и в предыдущем примере:
- чтение чужих данных
- обход ограничений поиска
- получение данных из других таблиц
- компрометация конфиденциальной информации.
- вплоть до выполнение команд на стороне сервера

7. как исправить:
- Использовать параметризованный запрос
- заменить строки 7 и 8 на 
```python
query = "SELECT id, username FROM users WHERE username = ?"
cur.execute(query, (name,))
```



---