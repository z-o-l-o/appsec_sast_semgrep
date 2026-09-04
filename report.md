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

4. что здесь потенциально небезопасного:

5. опасно ли это в данном учебном коде:

6. чем такая конструкция может быть опасна в реальном приложении: 



## 02. py-requests-no-verify

1. краткое описание из Semgrep (message/severity): 
- id: py-requests-no-verify
- message: "HTTP-запрос с verify=False (отключена проверка TLS-сертификата)"
- severity: WARNING

2. файл и номер строки:
- app.py
- 50┆ r = requests.get(url, verify=False)

3. соответствующий фрагмент кода:

4. что здесь потенциально небезопасного:

5. опасно ли это в данном учебном коде:

6. чем такая конструкция может быть опасна в реальном приложении: 



## 03. py-insecure-md5

1. краткое описание из Semgrep (message/severity): 
- message: "Использование hashlib.md5 для хеширования пароля или важных данных"
- severity: WARNING

2. файл и номер строки:
- usils.py
- 6┆ m = hashlib.md5()

3. соответствующий фрагмент кода:

4. что здесь потенциально небезопасного:

5. опасно ли это в данном учебном коде:

6. чем такая конструкция может быть опасна в реальном приложении: 



## 04. py-insecure-yaml-load

1. краткое описание из Semgrep (message/severity): 
- id: py-insecure-yaml-load
- message: "Небезопасный вызов yaml.load без безопасного Loader"
- severity: ERROR

2. файл и номер строки:
- usils.py
- 12┆ data = yaml.load(raw)

3. соответствующий фрагмент кода:

4. что здесь потенциально небезопасного:

5. опасно ли это в данном учебном коде:

6. чем такая конструкция может быть опасна в реальном приложении: 



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

4. что здесь потенциально небезопасного:

5. опасно ли это в данном учебном коде:

6. чем такая конструкция может быть опасна в реальном приложении: 


## 06. python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

1. краткое описание из Semgrep (message/severity): 
- id: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
- message: "Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language."
- severity: ERROR

2. файл и номер строки:
- insecure_db.py
- 8┆ cur.execute(query)


3. соответствующий фрагмент кода:

4. что здесь потенциально небезопасного:

5. опасно ли это в данном учебном коде:

6. чем такая конструкция может быть опасна в реальном приложении: 
---