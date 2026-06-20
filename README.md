# Тестовое для Фармстандарт - Зенин Арсений Олегович
работа выполнена на двух машинах управляющая машина farmstandart 192.168.0.12
и управляемая машина 192.168.0.13 farmstandart2

В ходе работы я повысил безопасность на Astra, настроил бд и пользователя аудитор
PostgreSQL, автоматизировал деплой через Ansible на тачке farmstandart2 и сделал дашборд с алертами в Grafana. 

---
СКРИНШОТЫ ВЫПОЛНЕНИЯ РАБОТЫ В .DOCX ФАЙЛЕ
## 1. Astra Linux (базовая безопасность)

1.1. Идентификация ОС
вбил команду `cat /etc/astra_version` увидел 1.8.1. Проверил, что модуль PARSEC загружен (`lsmod | grep parsec`). Целостность пакетов проверил через `dpkg -V`.

sudo systemctl status parsec

1.2. Аудит входов (логи успешных/неудачных попыток)
сделал правила auditd в `/etc/audit/rules.d/audit.rules`:
- логировал `execve` для `/bin/login`
- следил за `sshd` и за изменениями в логах
настроил конфиг `auditd.conf`, чтобы логи записывались в `/var/log/audit/secure`. сначала файл не появлялся, но после генерации событий (попробовал зайти пару раз с неправильным паролем он создался.

1.3. Политика паролей и отключение опасных служб
Прописал в `common-password` требования: минимально 8 символов, обязательные заглавные, строчные, цифры и спецсимволы. В `login.defs` выставил срок годности пароля 90 дней и прочие плюшки. Telnet/rlogin не нашёл, для страховки выполнил `apt-get remove --purge telnetd rsh-server` 

---

2. PostgreSQL (база, роли, логи, бэкап)

### 2.1. Создание базы и таблицы
через скрипт `setup.sql`: создал `security_db`, внутри таблицу `auth_log`., потом создал роль `auditor` с паролем `Auditor2026!` и дал ей только `SELECT` на таблицу.

команды чтобы создавать руками:

CREATE DATABASE security_db;
CREATE TABLE auth_log (...);
CREATE ROLE auditor WITH LOGIN PASSWORD 'pass';
GRANT SELECT ON auth_log TO auditor;

в pg_hba.conf запрещаю вход извне и ставлю вход только по сокету
local   security_db   auditor   scram-sha-256
host    security_db   auditor   0.0.0.0/0    reject

далее вкл логирование в postgresql.conf
log_statement = 'mod'
log_line_prefix = '%t %u %d %h'

сам скрипт

-- =============================================================================
-- setup.sql - Настройка базы данных security_db для аудита
-- Автор: Кандидат в АО «Фармстандарт»
-- Описание: Создание таблицы аудита, ролевой модели и прав доступа
-- =============================================================================

-- =============================================================================
-- 1. СОЗДАНИЕ БАЗЫ ДАННЫХ (если не существует)
-- =============================================================================

-- Создаем базу данных для хранения логов аудита
CREATE DATABASE security_db;

-- Переключаемся на созданную базу
\c security_db;

-- =============================================================================
-- 2. СОЗДАНИЕ ТАБЛИЦЫ ДЛЯ ЛОГОВ АУДИТА
-- =============================================================================

-- Создаем таблицу auth_log для хранения событий безопасности
CREATE TABLE IF NOT EXISTS auth_log (
    id BIGSERIAL PRIMARY KEY,                    -- Уникальный идентификатор записи
    username VARCHAR(50) NOT NULL,               -- Имя пользователя (обязательно)
    event_type VARCHAR(30) NOT NULL,             -- Тип события
    ip_address INET,                             -- IP-адрес (может быть NULL)
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- Время события
    user_agent TEXT,                             -- User-Agent браузера/клиента
    details JSONB                                -- Дополнительные данные в JSON (гибкость)
);

-- Создаем индексы для ускорения поиска
CREATE INDEX IF NOT EXISTS idx_auth_log_username ON auth_log(username);
CREATE INDEX IF NOT EXISTS idx_auth_log_timestamp ON auth_log(event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_auth_log_event_type ON auth_log(event_type);

-- Добавляем комментарии к таблице и полям (документация)
COMMENT ON TABLE auth_log IS 'Таблица для хранения событий аудита безопасности';
COMMENT ON COLUMN auth_log.username IS 'Имя пользователя, совершившего действие';
COMMENT ON COLUMN auth_log.event_type IS 'Тип события: LOGIN, LOGOUT, FAILED_LOGIN, ACCESS_DENIED';
COMMENT ON COLUMN auth_log.ip_address IS 'IP-адрес источника запроса';
COMMENT ON COLUMN auth_log.event_timestamp IS 'Время события с часовым поясом';
COMMENT ON COLUMN auth_log.user_agent IS 'User-Agent клиента';
COMMENT ON COLUMN auth_log.details IS 'Дополнительные данные в формате JSON';

-- =============================================================================
-- 3. СОЗДАНИЕ РОЛЕЙ И НАСТРОЙКА ПРИВИЛЕГИЙ
-- =============================================================================

-- 3.1. Создаем роль auditor (проверяющий)
CREATE ROLE auditor WITH 
    LOGIN                      -- Может подключаться
    PASSWORD 'StrongAuditorPassword123!'  -- Пароль (в продакшене - через Vault)
    NOSUPERUSER                -- Не суперпользователь
    NOCREATEDB                 -- Не может создавать БД
    NOCREATEROLE               -- Не может создавать роли
    INHERIT;                   -- Наследует права от родительских ролей

-- 3.2. Даем права на использование схемы public
GRANT USAGE ON SCHEMA public TO auditor;

-- 3.3. Даем права ТОЛЬКО на чтение таблицы auth_log
GRANT SELECT ON auth_log TO auditor;

-- 3.4. Явно запрещаем изменение данных в таблице auth_log
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON auth_log FROM auditor;

-- 3.5. Запрещаем доступ к остальным таблицам (если они появятся)
-- По умолчанию прав нет, но для надежности отзываем все права на схему
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM auditor;

-- 3.6. Но возвращаем SELECT на auth_log (важно!)
GRANT SELECT ON auth_log TO auditor;

-- =============================================================================
-- 4. НАСТРОЙКА ДОПОЛНИТЕЛЬНЫХ ПРАВИЛ (опционально)
-- =============================================================================

-- 4.1. Разрешаем auditor'у подключаться только к security_db
-- (Это ограничение на уровне подключения, но мы уже настроили в pg_hba.conf)
REVOKE CONNECT ON DATABASE postgres FROM auditor;
GRANT CONNECT ON DATABASE security_db TO auditor;

-- 4.2. Ограничиваем количество подключений для auditor (для безопасности)
ALTER ROLE auditor CONNECTION LIMIT 5;

-- 4.3. Устанавливаем время жизни сессии (бездействие) - 30 минут
ALTER ROLE auditor SET idle_in_transaction_session_timeout = '30min';

-- 4.4. Запрещаем auditor'у выполнять любые функции (для безопасности)
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM auditor;

-- =============================================================================
-- 5. ТЕСТОВЫЕ ДАННЫЕ (для проверки работы)
-- =============================================================================

-- Вставляем тестовые записи для демонстрации
INSERT INTO auth_log (username, event_type, ip_address, user_agent, details) VALUES
    ('admin', 'LOGIN', '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 
     '{"method": "password", "success": true}'),
    ('user1', 'LOGIN', '10.0.0.5', 'curl/7.68.0', 
     '{"method": "ssh_key", "success": true}'),
    ('hacker', 'FAILED_LOGIN', '45.33.22.11', 'Python-urllib/3.8', 
     '{"method": "password", "success": false, "reason": "wrong_password"}'),
    ('admin', 'LOGOUT', '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 
     '{"session_duration": "2h 15m"}'),
    ('user2', 'ACCESS_DENIED', '10.0.0.15', 'psql/14.5', 
     '{"table": "users", "action": "SELECT", "reason": "insufficient_privileges"}');

-- Выводим количество вставленных записей
SELECT COUNT(*) AS total_test_records FROM auth_log;

-- =============================================================================
-- 6. ПРОВЕРОЧНЫЕ ЗАПРОСЫ (для верификации)
-- =============================================================================

-- 6.1. Проверяем права auditor
-- Запрос должен вернуть: auditor имеет SELECT на auth_log
SELECT 
    grantee,
    table_name,
    privilege_type
FROM 
    information_schema.table_privileges 
WHERE 
    grantee = 'auditor' 
    AND table_name = 'auth_log';

-- 6.2. Проверяем структуру таблицы
SELECT 
    column_name,
    data_type,
    is_nullable,
    column_default
FROM 
    information_schema.columns 
WHERE 
    table_name = 'auth_log'
ORDER BY 
    ordinal_position;

-- 6.3. Проверяем индексы
SELECT 
    indexname,
    indexdef
FROM 
    pg_indexes 
WHERE 
    tablename = 'auth_log';

-- =============================================================================
-- 7. ИНСТРУКЦИИ ПО ЗАВЕРШЕНИЮ
-- =============================================================================

-- Для проверки подключения auditor:
-- psql -U auditor -d security_db -h /var/run/postgresql
-- 
-- Для проверки прав:
-- \dp auth_log
-- 
-- Для просмотра логов:
-- SELECT * FROM auth_log ORDER BY event_timestamp DESC LIMIT 10;
-- 
-- Для проверки, что INSERT запрещен:
-- INSERT INTO auth_log (username, event_type) VALUES ('test', 'LOGIN'); -- ОШИБКА!

-- =============================================================================
-- 8. ОЧИСТКА (опционально, для переустановки)
-- =============================================================================

-- Если нужно удалить всё и начать заново:
-- DROP TABLE IF EXISTS auth_log CASCADE;
-- DROP ROLE IF EXISTS auditor;
-- DROP DATABASE IF EXISTS security_db;

-- =============================================================================
-- КОНЕЦ ФАЙЛА setup.sql
-- =============================================================================



pg_dump -U postgres security_db > backup.sql
gpg --symmetric --cipher-algo AES256 backup.sql
rm backup.sql



**трудности с которыми столкнулся** 

при установке PostgreSQL система просила DVD-диск, потому что в `sources.list` был прописан локальный репозиторий, закомментировал `cdrom` и добавить официальные репозитории Astra, заработало.

2.2. Запрет внешних подключений для auditor
В `pg_hba.conf` добавил правила:
- `local` — разрешён только сокет
- `host` с `reject` на все IP — ни шагу в сторону
Проверил: локально заходит, по TCP — отказ.

2.3. Логирование всех запросов
В `postgresql.conf` включил `log_statement = 'all'`, чтобы писать все SELECT/INSERT/UPDATE/DELETE. Ещё выставил `log_parameter_max_length = 0`, чтобы пароли не светились в логах. Теперь логи лежат в `/var/log/postgresql/` и содержат только запросы без чувствительных данных.

2.4. Бэкап с шифрованием
Написал скрипт `backup_script.sh`, который делает дамп через `pg_dump`, шифрует его `gpg` (AES256) и удаляет незашифрованный файл.  Запустил и получил `.gpg`-файл с паролем.

**Проблемы* 
Была проблема, что `sudo` от postgres не работал, пришлось добавить пользователя в группу `sudo`. И забыл пароль от `frosdo` сбросил через `passwd` от рута.

---

3. Ansible

У меня две виртуалки: `farmstandart` (управляющая) и `farmstandart2` (целевая, IP 192.168.0.13). Задача — чтобы Ansible за один плейбук поставил Node Exporter, настроил конфиг и запустил.

3.1. Подготовка SSH
Сгенерил ключ, скопировал на вторую тачку через `ssh-copy-id`. Убедился, что ходит без пароля.

3.2. Инвентарь
В `inventory.ini` описал группу `farmstandart` с хостом, пользователем и явным `become`. В плейбуке тоже указал `hosts: farmstandart`.

**проблемы** 
сначала в плейбуке было `astra_servers`, а в файл инвентори по ошибке указал `farmstandart`  не матчились. Поправил и заработало.

3.3. Что делает плейбук
- Скачивает архив Node Exporter с GitHub, распаковывает в `/opt`
- Копирует бинарник в `/usr/local/bin`
- Создаёт папку для логов и `/etc/prometheus`
- Кладёт конфиг и systemd-юнит (из шаблонов)
- Настраивает iptables: пускает только с IP Прометеуса (у меня 10.10.10.10), остальных режет
- Включает и стартует сервис

3.4. Идемпотентность
Запустил с флагом `--check` — показало `changed=0`, при повторном прогоне ничего не меняет

**проблемы** на целевой машине sudo требовал пароль, хотя я думал, что настроил. Пришлось через `visudo` добавить `frosdo ALL=(ALL) NOPASSWD: ALL` — после этого Ansible перестал ругаться.

---

4. Grafana + Prometheus 
4.1. Источник данных
Добавил в Grafana источник Prometheus (http://localhost:9090). В `datasource.yaml` привёл команду для автоматического добавления через API

4.2. Дашборд для auditd
Создал панель с графиком метрики `node_systemd_unit_state{name="auditd"}`, добавил переменную `$instance`, чтобы можно было выбирать хост. Экспортировал в JSON, лежит в `dashboard.json`.

4.3. Алерт
Сделал правило в Prometheus: если состояние auditd не равно 1 в течение минуты триггерится алерт `AuditdServiceDown`. 
Правило в `prometheus_alert.yml` и еще для отправки на почту нужно настроить Alertmanager, в ТЗ не было указано, я указал, куда и что писать.

---

## Ошибки с которыми столкнулся и способы решения
1. **DVD-репозиторий вместо интернета** закомментил cdrom и добавил зеркала Astra.
2. **PostgreSQL не ставился** починил репозитории, как выше.
3. **sudo не работал у postgres и у frosdo** — добавил в группу sudo и прописал NOPASSWD.
4. **Забыл пароль** сбросил через root.
5. **Ansible не видел группу** поправил имя в плейбуке.
6. **Логи аудита не создавались**  оказалось, пишутся в `/var/log/audit/secure`, а не в `/var/log/secure` просто указал правильный путь в отчёте.

---

---

## Как запустить
1. Развернуть две Astra, настроить сеть.
2. На целевой поставить SSH, создать пользователя, скопировать ключи.
3. На управляющей установить Ansible, положить файлы из папки `ansible/`.
4. Запустить `ansible-playbook -i inventory.ini playbook.yml`.
5. Настроить Prometheus и Grafana (можно на той же управляющей).
6. Добавить дашборд и алерт.
