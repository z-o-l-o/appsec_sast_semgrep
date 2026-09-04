# appsec_sast_semgrep


AppSec Engineer : A deliberately insecure Python Flask application intended for training and hands-on practice with SAST analysis using Semgrep.
- Проект "AppSec course project - SAST Semgrep" 
- Курс: Защита приложений - AppSec Инженер
- @VladZolo 09/2026
- Учебный проект по работе с SAST Semgrep.

## 0. Задание: 
1. Вам выдан небольшой учебный проект на Python:
├─ app.py
├─ utils.py
├─ insecure_db.py

2. Код содержит намеренно небезопасные конструкции (работа с БД, сетевыми запросами, сериализацией и т.п.).

3. Ваша задача : 
- использовать готовые наборы правил Semgrep,
- Найти потенциальные уязвимости в этом проекте.
- Разобрать несколько найденных предупреждений:
    - что за проблема;
    - действительно ли это уязвимость;
    - чем она опасна в реальных приложениях.

---
@vladzolo (c) 2026