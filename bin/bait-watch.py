#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bait-watch — ловушка на ЧТЕНИЕ файлов-приманок (honeytokens).

МЕХАНИЗМ
    fanotify inode-marks. Метка ставится на КОНКРЕТНЫЙ inode, поэтому событие
    ловится независимо от того, из какого mount namespace файл открыли: чтение
    из docker-контейнера через bind-mount даёт тот же inode и то же событие.
    Это надёжнее inotify (которого на хосте нет) и не требует auditd.

    Основной режим — FAN_OPEN_PERM (класс CONTENT): ядро ПРИОСТАНАВЛИВАЕТ
    открывающий процесс, пока мы не ответим. Благодаря этому /proc/<pid>
    гарантированно ещё жив, и мы успеваем снять форензику даже с процесса
    вида `cat ~/.aws/credentials`, который живёт 2 мс.
    ⚠️ Мы ВСЕГДА отвечаем FAN_ALLOW (ничего не блокируем) и делаем это ДО
    любой медленной работы: Telegram и `ss` вынесены в фоновый поток.
    Если ядро/права не дают PERM — автоматический откат в режим наблюдения
    FAN_OPEN (тогда форензика по короткоживущим процессам может быть неполной).

Требует CAP_SYS_ADMIN → запускается systemd-юнитом от root.

ЧТО СЧИТАЕТСЯ ТРЕВОГОЙ (правка 28.07.2026 — ложняки)
    Решение принимается НЕ по имени программы (оно подделывается: вредонос
    25.07 маскировался под irqbalance/atd/[kworker], а секреты собирал обычным
    поиском). Смотрим на ФОРМУ поведения по /proc/<pid>/io:
      • «обход каталога» — между приманками процесс прочитал горы обычных
        файлов (рекурсивный grep по каталогу с проектами) → WARN, ОДНО письмо
        на весь проход;
      • «прицельный сбор» — открывает только файлы-секреты, ничего рядом
        (скрипт стилера) → CRIT;
      • слова secret/token/id_rsa/.env… в самой команде → CRIT всегда,
        включая режим обслуживания;
      • программа открыла свой же конфиг (git→.netrc, npm→.npmrc) → журнал.
    Поисковики grep/find/rg В БЕЛЫЙ СПИСОК ПО ИМЕНИ НЕ ВНОСЯТСЯ.

ДВЕ ДЫРЫ, ЗАКРЫТЫЕ 28.07.2026 ПОСЛЕ ЖИВЫХ ТЕСТОВ КРАСНОЙ КОМАНДЫ
    B. «Разбавление мусором». Вор читал 4 приманки, подмешивая между ними
       десятки мегабайт обычных файлов — по объёму постороннего чтения это
       выглядело как обход каталога (WARN), а в окне обслуживания уходило
       в тишину. Закрыто проверкой ПОЛНОТЫ обхода (Session.coverage):
       рекурсивный поиск, зайдя в каталог, читает его ЦЕЛИКОМ, поэтому
       задевает ВСЕ приманки этого каталога — на 6 реальных прогонах grep
       покрытие ровно 1.00. Вор берёт из каталога только нужное — покрытие
       0.44–0.75. Пропущенный сосед + два разных каталога + ≥2 «секретных»
       приманки = CRIT, сколько бы мусора ни было прочитано, и окно
       обслуживания это НЕ прячет.
    D. «Подделка имени из белого списка». Одним prctl() процесс называется
       `updatedb` и получает INFO. Закрыто проверкой ПРОИСХОЖДЕНИЯ бинаря
       (exe_origin/comm_trusted): системный каталог + владелец root + нет
       записи для чужих + имя обязано совпасть с ожидаемым путём инструмента
       + бинарь числится в пакете dpkg. Имя без совпадения пути = НЕ доверен.

РЕЖИМЫ
    bait-watch.py --daemon      # рабочий режим (systemd)
    bait-watch.py --digest [ч]  # сводка за сутки (тихие классы видны ТОЛЬКО тут)
    bait-watch.py --selftest    # проверка детекта БЕЗ отправки в Telegram (режим тишины)
    bait-watch.py --status      # что под наблюдением
    bait-watch.py --test-tg     # проверить доставку в Telegram
    bait-watch.py --maint 600 "зачем"   # окно планового обслуживания (root)
    bait-watch.py --maint-off           # снять окно досрочно

⚠️ Скрипт НЕ трогает malware-watch.sh, только переиспользует его токен.
"""

import ctypes, ctypes.util, errno, fcntl, hashlib, html, json, os, queue, re
import select, signal, struct, subprocess, sys, threading, time
import urllib.parse, urllib.request
from collections import defaultdict, deque

# ────────────────────────────── конфигурация ──────────────────────────────
BAITS_LIST   = os.environ.get("BAIT_LIST",   "/etc/bait-watch/baits.list")
ALLOW_LIST   = os.environ.get("BAIT_ALLOW",  "/etc/bait-watch/allow.list")
TG_ENV_FILE  = os.environ.get("BAIT_TG_ENV", "/etc/malware-watch.env")
LOG_DIR      = os.environ.get("BAIT_LOG_DIR",   "/var/log/bait-watch")
STATE_DIR    = os.environ.get("BAIT_STATE_DIR", "/var/lib/bait-watch")
EVENTS_LOG   = os.path.join(LOG_DIR, "events.jsonl")

DEDUP_SECONDS       = 1800 # одна приманка+процесс — не чаще раза в 30 мин
CRIT_DEDUP_SECONDS  = 1800 # тот же процесс с тем же набором — раз в 30 мин
SWEEP_COUNT         = 3    # >=3 разных приманок за сессию = прочёс
SWEEP_WINDOW        = 900  # окно жизни сессии-прочёса (рекурсивный grep идёт минутами)
MAX_ALERTS_PER_HOUR = 12   # предохранитель от лавины

# ── агрегация ──────────────────────────────────────────────────────────────
# Рекурсивный обход большого дерева выдаёт приманки НЕ подряд: между двумя
# попаданиями grep успевает прочитать сотни мегабайт (инцидент 28.07: 18 событий
# растянулись на 106 с). Прежнее окно склейки 5 с рвало это на 15 сообщений.
AGG_QUIET   = 12.0   # тишина по сессии, после которой отправляем накопленное
AGG_MAX     = 120.0  # но не держим дольше двух минут
# После отправки тревоги по сессии молчим по ней STICKY_SECONDS: продолжение
# того же прочёса пишется только в журнал. Пробивается ТОЛЬКО эскалацией
# (WARN → CRIT), чтобы «медленный» стилер не спрятался за первым мягким письмом.
STICKY_SECONDS = 1800

# ── различение «обход каталога» vs «прицельный сбор секретов» ──────────────
# Ключевой сигнал — СКОЛЬКО ПОСТОРОННЕГО процесс прочитал между приманками
# (/proc/<pid>/io: rchar/syscr). Рекурсивный поиск читает всё дерево подряд,
# приманки в нём — доли процента. Стилер открывает ТОЛЬКО секреты: между
# приманками у него почти нулевой трафик. Имя процесса при этом не важно —
# именно поэтому grep/find НЕ в белом списке (их использовал и бот 25.07).
WALK_BYTES   = 8 * 1024 * 1024  # >8 МБ постороннего чтения = обход дерева
WALK_SYSCR   = 400              # либо >400 посторонних read-syscall'ов
DIRECT_BYTES = 512 * 1024       # <512 КБ постороннего = шёл прицельно
DIRECT_SYSCR = 120
# Сколько процесс прочитал ДО первой приманки. Раньше это не учитывалось
# вообще («интерпретатор читает свою stdlib»), и обход, который успел
# перелопатить дерево ПЕРЕД тем как задеть приманку, выглядел прицельным
# сбором → CRIT. Замер 28.07: у обхода `grep` перед первой приманкой 19.5 МБ,
# у ВСЕХ остальных (python-стилеры, npm, git, самотест) — не больше 2.0 МБ.
# Порог 8 МБ лежит между этими группами с большим запасом.
# Порог отдельный от WALK_BYTES и НАМЕРЕННО ниже. Замеры 28.07:
#   • стилеры/инструменты до первой приманки: 0.0–2.0 МБ (максимум — запуск
#     самого интерпретатора python);
#   • обход дерева: 6.3 МБ по небольшому каталогу и 19.5 МБ по среднему.
# 8 МБ пропускали обход по НЕБОЛЬШОМУ дереву в «прицельный сбор» (поймано
# живым прогоном: `grep -rl` по каталогу на 6.3 МБ получил форму direct).
# 4 МБ отделяет обе группы с двукратным запасом в каждую сторону.
PREWALK_BYTES = 4 * 1024 * 1024

# ── сколько ловушке ВООБЩЕ позволено писать в Telegram ─────────────────────
# 28.07 ловушка стала самым громким источником в системе. Разбор журнала:
# из 39 тревог за день 27 — наши же учения, а обычный фон давал 2 сообщения
# за 7.4 ч (≈6.5 в сутки). Чтобы фон не мог вырасти незаметно, вводим
# жёсткие потолки: сколько сообщений класса допустимо за сутки.
#   0 = класс НЕ шлётся вовсе (журнал + утренняя сводка).
# «Сплошной обход каталога» (WARN) — это наш собственный поиск по папкам,
# ему в Telegram делать нечего. Громким остаётся прицельный сбор.
# Потолок держим ПО ПРАВИЛУ, а не по классу важности: иначе самый шумный
# вердикт («поведение непонятное», это наш же рекурсивный поиск) съедает
# суточный лимит, и на настоящую охоту сообщений уже не остаётся — так и
# вышло на прогоне журнала: 6 срабатываний hunt подряд упёрлись в потолок,
# выбранный учебными прогонами.
DAILY_MAX = {
    "deleted": 4,   # программа стёрла свой файл с диска — почти всегда зловред
    "hunt":    4,   # выборочная охота, замаскированная мусором
    "direct":  4,   # прицельный сбор секретов
    "intent":  3,   # в самой команде ищут secret/token/id_rsa
}
# walk и unknown своего потолка не имеют: они уходят в ОБЩУЮ очередь сторожа
# (AMBER_RULES ниже), и частоту им задаёт он — раз в сутки на отпечаток.
DAILY_MAX_TOTAL = 8   # общий предохранитель — ТОЛЬКО на шумные классы

# ⚠️ Правила, которые описывают КРАЖУ В ПРОЦЕССЕ. Общий предохранитель на них
# НЕ распространяется и они его НЕ расходуют: задавить настоящую тревогу ради
# тишины хуже, чем лишний раз шумнуть. Свой суточный потолок у каждого
# остаётся (по 4), плюс подавление повторов по подписи.
# Найдено проверкой 28.07: до этой правки шумные классы выбирали общий предел,
# и следующий за ними прицельный сбор глушился «потолком» — то есть ловушка
# молчала ровно тогда, когда была нужна.
BREAKTHROUGH = {"deleted", "direct", "hunt"}

# ── всё, что НЕ кража, уходит в ОБЩУЮ очередь соседнего сторожа ────────────
# `malware-watch.sh queue-amber <заголовок> <текст> [код]` кладёт факт в общий
# механизм: один и тот же отпечаток не чаще раза в сутки (AMBER_REPEAT),
# общий бюджет некрасных (AMBER_BUDGET) и общие тихие часы из
# /etc/malware-watch.env — и всё склеивается в ОДНУ утреннюю сводку.
# Проверено по коду сторожа: queue-amber НИЧЕГО не отправляет сам, только
# дописывает строку в очередь сводки, поэтому вызов безопасен и под тишиной.
MW_SCRIPT   = os.environ.get("BAIT_MW", "/usr/local/sbin/malware-watch.sh")
AMBER_RULES = {"walk", "unknown", "intent_soft"}
# ⚠️ Отпечаток в общей очереди считается ПО ЗАГОЛОВКУ, поэтому заголовок
# постоянный для класса, а всё изменчивое (программа, файлы, объёмы) — в
# тексте. Иначе «раз в сутки» превратится в «на каждый прогон поиска».
AMBER_TITLE = {
    "walk":    "Приманки задело сплошным поиском по папкам",
    "unknown": "Приманку открыла незнакомая программа",
    "intent_soft": "Кто-то искал секреты по имени файла — похоже, свои",
}
# Как часто мы вообще ДЁРГАЕМ соседний скрипт. Решение «раз в сутки» принимает
# он сам; нам достаточно не плодить запуски процесса на каждый прогон поиска.
AMBER_CALL_GAP = 3600
# Одна и та же подпись (правило + программа + набор приманок) — не чаще
# раза в сутки: программа, лезущая в приманки весь день, даёт ОДНО сообщение.
SIG_TTL = 86400

# ── ДЫРА B: «разбавление мусором» ──────────────────────────────────────────
# Объём постороннего чтения — метрика, которой вор УПРАВЛЯЕТ: достаточно
# читать в цикле большой файл между секретами, и любой сбор выглядит как
# обход дерева (красная команда 28.07: 4 приманки + 19–57 МБ мусора → WARN,
# а в окне обслуживания → тишина).
#
# Метрика, которой вор НЕ управляет, — ПОЛНОТА обхода. Рекурсивный поиск
# заходит в каталог и читает его целиком, поэтому задевает ВСЕ приманки
# этого каталога. Замер по журналу за 28.07 (6 реальных прогонов grep,
# от 8 до 18 приманок, до 163 МБ постороннего чтения): покрытие соседей
# РОВНО 1.00 в каждом. У всех прогонов красной команды — 0.44…0.75.
BAIT_VALUE_RE = re.compile(          # приманки, в которых лежит ключевой материал
    r"(?i)(/\.ssh/id_(rsa|ed25519|ecdsa)$|/\.aws/credentials$|/\.git-credentials$"
    r"|/passphrase\.txt$|/wallet\.dat$|/\.netrc$|/\.npmrc$|/\.pypirc$"
    r"|/rclone\.conf$|/\.docker/config\.json$|/\.kube/config$|/\.env(\.|$))")
# ЯДРО — файлы, в которых лежит только ключевой материал и ничего больше.
# Законному инструменту незачем читать ДВА таких файла разом: конфига у него
# тут нет, читать их «заодно» не приходится.
BAIT_CORE_RE = re.compile(
    r"(?i)(/\.ssh/id_(rsa|ed25519|ecdsa)$|/\.aws/credentials$"
    r"|/\.git-credentials$|/passphrase\.txt$)")
HUNT_MIN_BAITS = 3     # обычный порог охоты: меньше трёх файлов — не улика
HUNT_MIN_CORE  = 2     # ...либо два файла из ЯДРА, тогда хватает и двух
HUNT_VALUABLE = 2      # сколько «секретных» приманок за сессию делают это охотой
HUNT_DIRS     = 2      # прыжки минимум по двум разным каталогам
HUNT_COVER    = 0.80   # покрытие соседей ниже этого = каталог читали ВЫБОРОЧНО

# Какие приманки лежат в одном каталоге (заполняется при старте из baits.list).
BAIT_SIBLINGS = {}


def load_geography(baits):
    """География ловушки: каталог → все приманки в нём.

    Нужна для проверки полноты обхода: если процесс взял из каталога одну
    приманку, а вторую рядом не тронул — он ВЫБИРАЛ, а не шёл подряд.
    """
    BAIT_SIBLINGS.clear()
    for b in baits:
        BAIT_SIBLINGS.setdefault(os.path.dirname(b), set()).add(b)


# ── ДЫРА D: имя процесса ≠ доказательство ──────────────────────────────────
# comm подделывается одним prctl(PR_SET_NAME): красная команда 28.07 запустила
# /usr/bin/python3.12 под именем `updatedb` и тихо унесла 2 приманки (INFO).
# Поэтому запись `comm:` в белом списке теперь только ПОДСКАЗКА, а доверие
# даёт сам бинарь: системный каталог + владелец root + никакой записи для
# чужих + путь, ожидаемый именно для этого инструмента + принадлежность пакету.
TRUSTED_EXE_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                    "/usr/lib/", "/usr/libexec/",
                    "/usr/local/bin/", "/usr/local/sbin/")

# Ожидаемый путь для инструментов, которых пускаем ПО ИМЕНИ. comm в /proc
# обрезан до 15 символов — ключи держим и в полном, и в обрезанном виде.
COMM_EXPECT = {
    "updatedb":        (r"^/usr/bin/updatedb(\.mlocate|\.plocate)?$",),
    "updatedb.mlocate": (r"^/usr/bin/updatedb\.mlocate$",),
    "updatedb.mlocat": (r"^/usr/bin/updatedb\.mlocate$",),
    "updatedb.plocat": (r"^/usr/bin/updatedb\.plocate$",),
    "plocate":         (r"^/usr/bin/plocate$",),
    "mlocate":         (r"^/usr/bin/mlocate$",),
    "locate":          (r"^/usr/bin/(m|p)?locate$",),
    "clamscan":        (r"^/usr/bin/clamscan$",),
    "clamd":           (r"^/usr/s?bin/clamd$",),
    "clamdscan":       (r"^/usr/bin/clamdscan$",),
    "freshclam":       (r"^/usr/bin/freshclam$",),
}
COMM_EXPECT = {k: tuple(re.compile(r) for r in v) for k, v in COMM_EXPECT.items()}

_pkg_cache, _pkg_lock = {}, threading.Lock()


def pkg_owned(exe):
    """Числится ли бинарь в системном пакете. True/False/None (dpkg недоступен).

    Кэш вечный: состав пакетов между событиями не меняется, а dpkg -S стоит
    ~0.12 с — в горячем пути это дорого.
    """
    with _pkg_lock:
        if exe in _pkg_cache:
            return _pkg_cache[exe]
    res = None
    try:
        r = subprocess.run(["dpkg", "-S", os.path.realpath(exe)],
                           capture_output=True, text=True, timeout=5)
        res = (r.returncode == 0)
    except Exception:
        res = None          # нет dpkg — это не улика ни в одну сторону
    with _pkg_lock:
        _pkg_cache[exe] = res
    return res


def exe_origin(p):
    """Происхождение бинаря процесса. → ("exe" | "weak" | None, причина).

    Проверяем ФАЙЛ, а не имя. Три исхода:
      "exe"  — это ровно наш файл: тот же inode, что у бинаря на хосте,
               владелец root, лежит в системном каталоге, чужим не пишется;
      "weak" — путь совпал, но файл ДРУГОЙ (типично для процесса из
               контейнера, где по тому же пути своя копия). Инструмент узнан,
               но ручаться за него нельзя — доверие как за совпадение по имени;
      None   — доверия нет вовсе.
    """
    exe = p.get("exe") or ""
    if not exe or exe == "(недоступен)":
        return None, "файл программы недоступен"
    if exe.endswith(" (deleted)"):
        return None, "бинарь удалён с диска"
    if not exe.startswith(TRUSTED_EXE_DIRS):
        return None, f"бинарь вне системных каталогов: {exe}"
    est = p.get("exe_st")
    if not est:
        # Снимок не сняли — так бывает только в запасном режиме наблюдения
        # (FAN_OPEN без приостановки), когда короткоживущий процесс успел
        # умереть. Тогда судим по файлу на хосте, но полного доверия не даём.
        if p.get("alive"):
            return None, "не удалось снять сведения о файле программы"
        try:
            st = os.stat(exe)
        except OSError:
            return None, f"бинарь не читается: {exe}"
        if st.st_uid != 0 or (st.st_mode & 0o022):
            return None, f"бинарь не под контролем root: {exe}"
        return "weak", (f"процесс завершился раньше, чем мы посмотрели на его "
                        f"файл — сверялись только с путём {exe}")
    dev, ino, uid, mode = est
    if uid != 0:
        return None, f"бинарь принадлежит uid {uid}, а не root: {exe}"
    if mode & 0o022:
        return None, f"бинарь доступен на запись не только root: {exe}"
    try:
        st = os.stat(exe)
    except OSError:
        return "weak", (f"файла {exe} на хосте нет — процесс запустил свою "
                        f"копию в отдельном namespace")
    if (st.st_dev, st.st_ino) != (dev, ino):
        return "weak", (f"путь {exe} совпал, но запущен ДРУГОЙ файл (своя копия "
                        f"в контейнере), а не наш проверенный бинарь")
    return "exe", exe


def comm_trusted(p):
    """Можно ли верить ИМЕНИ процесса. → ("name" | None, причина).

    Имя без совпадения реального пути — не доверенный, даже если оно есть
    в белом списке. Ровно этим обошли ловушку 28.07. Для разрешения ПО ИМЕНИ
    «своей копии» мало: нужен именно наш файл.
    """
    exe, comm = p.get("exe") or "", p.get("comm") or ""
    # ⚠️ Сначала сверяем ИМЯ с ожидаемым путём инструмента и только потом
    # происхождение файла: так в тревогу попадает самая говорящая причина
    # («назвался updatedb, а запущен python3»), а не общая про namespace.
    pats = COMM_EXPECT.get(comm) or COMM_EXPECT.get(comm[:15])
    if pats:
        if not any(rx.match(exe) for rx in pats):
            return None, (f"процесс назвался «{comm}», но это не тот файл: "
                          f"запущен {exe}")
    else:
        base = os.path.basename(exe)
        if base[:15] != comm[:15]:
            return None, (f"имя процесса «{comm}» не совпадает с именем "
                          f"бинаря: запущен {exe}")
    lvl, why = exe_origin(p)
    if lvl != "exe":
        return None, why
    if pkg_owned(exe) is False:
        return None, f"бинарь не принадлежит ни одному системному пакету: {exe}"
    return "name", exe

# Маркеры «ищут именно секреты» в командной строке. Совпадение = CRIT всегда,
# даже в режиме обслуживания и даже если это обход дерева: ровно так работал
# скрипт бота 25.07 (`*secret*`, `*token*`, `~/.ssh/id_*`).
SECRET_INTENT_RE = re.compile(
    r"(?i)(secret|token|passw|passphrase|credential|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY|id_rsa|id_ed25519|id_ecdsa"
    r"|authorized_keys|known_hosts|\.pem\b|\.p12\b|htpasswd|shadow\b"
    r"|\.env\b|\.npmrc|\.netrc|\.pypirc|git-credentials|rclone\.conf"
    r"|wallet\.dat|\.aws|\.ssh|\.kube|\.docker/config"
    r"|AKIA[0-9A-Z]{8}|ghp_|xox[baprs]-)")

# Режим обслуживания: наш инструмент перед широким поиском объявляет окно.
# Файл лежит в /run (писать может только root) и САМОПРОТУХАЕТ.
# ⚠️ Понижает ТОЛЬКО класс «обход каталога». Прицельный сбор и удалённый
# бинарь пробивают режим обслуживания насквозь.
MAINT_FLAG    = os.environ.get("BAIT_MAINT_FLAG", "/run/bait-watch.maint")
MAINT_MAX_AGE = 1800   # жёсткий потолок окна, даже если в файле просили больше

# Режим тишины: пока существует этот файл, события ПИШУТСЯ В ЖУРНАЛ, но в
# Telegram НЕ уходят. Ставится самотестом, чтобы проверка не будила оператора.
# ⚠️ Флаг САМОПРОТУХАЕТ через QUIET_MAX_AGE секунд — забытый файл не должен
# ослепить ловушку навсегда.
QUIET_FLAG    = os.environ.get("BAIT_QUIET_FLAG", "/run/bait-watch.quiet")
QUIET_MAX_AGE = 600


def quiet_active():
    """True, если включён режим тишины (и флаг ещё не протух)."""
    try:
        age = time.time() - os.stat(QUIET_FLAG).st_mtime
    except OSError:
        return False
    if age > QUIET_MAX_AGE:
        return False
    return True


def maint_active():
    """Активно ли окно планового обслуживания.

    Возвращает dict с описанием окна или None. Живёт не дольше min(ttl из
    файла, MAINT_MAX_AGE) — забытый флаг сам протухает и не ослепляет ловушку.
    """
    try:
        st = os.stat(MAINT_FLAG)
        raw = open(MAINT_FLAG).read()[:500]
    except OSError:
        return None
    try:
        info = json.loads(raw)
        if not isinstance(info, dict):
            raise ValueError
    except Exception:
        info = {"reason": raw.strip()[:200]}
    ttl = min(int(info.get("ttl") or MAINT_MAX_AGE), MAINT_MAX_AGE)
    age = time.time() - st.st_mtime
    if age > ttl:
        return None
    info["age"] = int(age)
    info["left"] = int(ttl - age)
    return info


# ── «программа читает свой же файл настроек» ───────────────────────────────
# Единственный вид послабления по имени программы, и он узкий: точный путь
# бинаря + ровно ТОТ файл, который эта программа обязана читать сама, + за
# сессию она не полезла ни в одну ЧУЖУЮ приманку. Появился из журнала:
# git-remote-https читает .netrc при каждом push, npm читает .npmrc.
OWNER_MAP = (
    (re.compile(r"^/usr/(lib/git-core|bin)/git(-remote-http.*|-credential.*)?$"),
     (".netrc", ".git-credentials")),
    (re.compile(r"^/usr/(bin|local/bin)/(node|npm|npx|yarn|pnpm)$"),        (".npmrc",)),
    (re.compile(r"^/usr/lib/node_modules/npm/.*$"),                        (".npmrc",)),
    (re.compile(r"^/usr/bin/python3(\.\d+)?$|^/usr/(bin|local/bin)/(pip|pip3|twine)$"),
     (".pypirc",)),
    (re.compile(r"^/usr/bin/(docker|dockerd|docker-compose)$"),  ("config.json",)),
    (re.compile(r"^/usr/(bin|local/bin)/(kubectl|helm|k9s)$"),   ("config",)),
    (re.compile(r"^/usr/(bin|local/bin)/aws$"),                  ("credentials", "config")),
    (re.compile(r"^/usr/(bin|local/bin)/rclone$"),               ("rclone.conf",)),
)


def owned_config(exe, bait):
    """True, если bait — это собственный конфиг программы exe."""
    base = os.path.basename(bait or "")
    for rx, names in OWNER_MAP:
        if rx.match(exe or "") and base in names:
            return True
    return False


def secret_intent(p):
    """Маркеры прицельного поиска секретов в командной строке процесса."""
    cmd = p.get("cmdline") or p.get("session_leader") or ""
    return sorted(set(m.group(0)[:32] for m in SECRET_INTENT_RE.finditer(cmd)))[:6]


def read_io(pid):
    """rchar/syscr процесса. Показывает, сколько ПОСТОРОННЕГО он читает."""
    try:
        d = {}
        with open(f"/proc/{pid}/io") as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in ("rchar", "syscr"):
                    d[k] = int(v)
        return d.get("rchar", 0), d.get("syscr", 0)
    except Exception:
        return -1, -1


# ────────────────────────────── fanotify (ctypes) ─────────────────────────
_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

SYS_fanotify_init, SYS_fanotify_mark = 300, 301   # x86_64

FAN_CLOEXEC, FAN_NONBLOCK = 0x00000001, 0x00000002
FAN_CLASS_NOTIF, FAN_CLASS_CONTENT = 0x00000000, 0x00000004
FAN_MARK_ADD = 0x00000001

FAN_ACCESS, FAN_MODIFY, FAN_OPEN = 0x00000001, 0x00000002, 0x00000020
FAN_OPEN_PERM, FAN_ACCESS_PERM = 0x00010000, 0x00020000
FAN_ALLOW, FAN_DENY = 0x01, 0x02

O_RDONLY, O_LARGEFILE, O_CLOEXEC = 0o0, 0o100000, 0o2000000
AT_FDCWD = -100
METADATA_FMT, METADATA_LEN = "=IBBHQii", 24
RESPONSE_FMT = "=iI"


def _sys(*args, argtypes, restype=ctypes.c_int):
    _libc.syscall.argtypes = argtypes
    _libc.syscall.restype = restype
    ctypes.set_errno(0)
    return _libc.syscall(*args)


def fanotify_init(flags, event_f_flags):
    r = _sys(SYS_fanotify_init, flags, event_f_flags,
             argtypes=[ctypes.c_long, ctypes.c_uint, ctypes.c_uint])
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e), "fanotify_init")
    return r


def fanotify_mark(fd, flags, mask, path):
    r = _sys(SYS_fanotify_mark, fd, flags, ctypes.c_uint64(mask), AT_FDCWD,
             path.encode() if isinstance(path, str) else path,
             argtypes=[ctypes.c_long, ctypes.c_int, ctypes.c_uint,
                       ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p])
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e), path)
    return r


# ────────────────────────────── утилиты ───────────────────────────────────
_log_lock = threading.Lock()


def log_line(obj):
    obj.setdefault("ts", time.time())
    obj.setdefault("ts_iso", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with _log_lock, open(EVENTS_LOG, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        print(f"[warn] не смог записать лог: {e}", file=sys.stderr)


def read_env_file(path):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return out


def load_list(path):
    items = []
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    items.append(line)
    except FileNotFoundError:
        pass
    return items


# ─────────────────── форензика: БЫСТРАЯ часть (блокирующий путь) ──────────
def fast_forensics(pid):
    """Только чтение /proc — без subprocess и без сети.
    Выполняется, пока открывающий процесс приостановлен ядром."""
    p = {"pid": pid, "alive": True}
    base = f"/proc/{pid}"
    try:
        with open(f"{base}/cmdline", "rb") as f:
            p["cmdline"] = f.read().replace(b"\x00", b" ").decode(
                errors="replace").strip()[:400]
    except Exception:
        p["cmdline"] = ""
        p["alive"] = False
    for key, rel in (("exe", "exe"), ("cwd", "cwd")):
        try:
            p[key] = os.readlink(f"{base}/{rel}")
        except Exception:
            p[key] = "(недоступен)"
    try:
        with open(f"{base}/status") as f:
            for line in f:
                if line.startswith("Name:"):
                    p["comm"] = line.split()[1]
                elif line.startswith("Uid:"):
                    p["uid"] = int(line.split()[1])
                elif line.startswith("PPid:"):
                    p["ppid"] = int(line.split()[1])
                elif line.startswith("Groups:"):
                    break
    except Exception:
        pass
    p.setdefault("comm", "?"); p.setdefault("uid", -1); p.setdefault("ppid", 0)

    # бинарь удалён с диска = почти всегда зловред (класс Mirai, инцидент 25.07)
    p["exe_deleted"] = p["exe"].endswith(" (deleted)")

    # Кто на самом деле запущен. Снимаем ЗДЕСЬ, пока процесс приостановлен
    # ядром: /proc/<pid>/exe ведёт к настоящему файлу в ЕГО namespace, а тот
    # же путь строкой у нас на хосте может оказаться совсем другим файлом.
    # Проверено 28.07: в контейнере по разрешённому пути
    # …/some-cli/bin/some-cli.exe лежит СВОЯ копия (другое устройство,
    # другой inode, даже другой размер) — по одному лишь пути белый список
    # доверял бы чужому файлу.
    try:
        est = os.stat(f"{base}/exe")
        p["exe_st"] = [est.st_dev, est.st_ino, est.st_uid, est.st_mode]
    except Exception:
        p["exe_st"] = None

    # сколько процесс прочитал ВСЕГО к этому моменту — снимаем, пока он
    # приостановлен ядром. По разнице между попаданиями видно, ходит он по
    # дереву (читает кучу постороннего) или лезет прицельно в секреты.
    p["rchar"], p["syscr"] = read_io(pid)

    # pgrp/session — по ним склеиваем ОДИН прочёс, даже если стилер запускает
    # отдельный процесс на каждый файл (`for f in …; do cat $f; done`)
    p["pgrp"] = p["session"] = 0
    try:
        with open(f"{base}/stat") as f:
            raw = f.read()
        tail = raw[raw.rfind(")") + 2:].split()  # comm может содержать пробелы
        p["pgrp"], p["session"] = int(tail[2]), int(tail[3])
    except Exception:
        pass

    # сырой cgroup + mount namespace — расшифруем в фоне
    try:
        with open(f"{base}/cgroup") as f:
            p["_cgroup"] = f.read()[:400]
    except Exception:
        p["_cgroup"] = ""
    try:
        p["_ns_mnt"] = os.readlink(f"{base}/ns/mnt")
    except Exception:
        p["_ns_mnt"] = ""

    # цепочка родителей — по ней видно, откуда пришёл шелл
    chain, cur = [], p["ppid"]
    for _ in range(6):
        if cur <= 0:
            break
        try:
            nm, nxt = "?", 0
            with open(f"/proc/{cur}/status") as f:
                for line in f:
                    if line.startswith("Name:"):
                        nm = line.split()[1]
                    elif line.startswith("PPid:"):
                        nxt = int(line.split()[1]); break
            chain.append(f"{nm}({cur})")
            cur = nxt
        except Exception:
            break
    p["parents"] = " ← ".join(chain)

    # если процесс уже мёртв — вытащим лидера сессии (живёт дольше)
    p["session_leader"] = ""
    if not p["cmdline"] and p["session"]:
        try:
            with open(f"/proc/{p['session']}/cmdline", "rb") as f:
                p["session_leader"] = f.read().replace(b"\x00", b" ").decode(
                    errors="replace").strip()[:200]
        except Exception:
            pass
    return p


# ─────────────────── форензика: МЕДЛЕННАЯ часть (фоновый поток) ───────────
_container_cache, _container_cache_ts, _cc_lock = {}, 0.0, threading.Lock()


def container_name_by_id(cid):
    """id контейнера → имя (кэш 60 с)."""
    global _container_cache, _container_cache_ts
    with _cc_lock:
        if time.time() - _container_cache_ts > 60:
            try:
                out = subprocess.run(
                    ["docker", "ps", "--format", "{{.ID}} {{.Names}}", "--no-trunc"],
                    capture_output=True, text=True, timeout=5).stdout
                m = {}
                for line in out.strip().splitlines():
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        m[parts[0]] = parts[1]
                _container_cache = m
            except Exception:
                pass
            _container_cache_ts = time.time()
        cache = dict(_container_cache)
    for k, v in cache.items():
        if k.startswith(cid) or cid.startswith(k[:12]):
            return v
    return None


_host_ns_mnt = None


def enrich(p):
    """Дорогая часть: имя контейнера (docker ps) и сетевые соединения (ss)."""
    global _host_ns_mnt
    p["where"], p["container"] = "хост", None
    m = re.search(r"docker[-/]([0-9a-f]{12,64})", p.get("_cgroup", ""))
    if m:
        cid = m.group(1)
        p["container"] = container_name_by_id(cid) or cid[:12]
        p["where"] = f"контейнер {p['container']}"
    else:
        if _host_ns_mnt is None:
            try:
                _host_ns_mnt = os.readlink("/proc/1/ns/mnt")
            except Exception:
                _host_ns_mnt = ""
        if p.get("_ns_mnt") and _host_ns_mnt and p["_ns_mnt"] != _host_ns_mnt:
            p["where"] = "изолированный namespace (не хост)"
    try:
        out = subprocess.run(["ss", "-tnp"], capture_output=True,
                             text=True, timeout=4).stdout
        p["connections"] = [f"{l.split()[4]}→{l.split()[5]}"
                            for l in out.splitlines()
                            if f"pid={p['pid']}," in l][:5]
    except Exception:
        p["connections"] = []
    p.pop("_cgroup", None); p.pop("_ns_mnt", None)
    return p


# ────────────────────────────── Telegram ──────────────────────────────────
def tg_send(text):
    # ОБЩИЙ ТИХИЙ РЕЖИМ (тот же файл, что у malware-watch): unix-время, до которого
    # НЕ слать в Telegram. Детект и журнал работают, заглушённое пишется в muted.log.
    # FAIL-SAFE: «не смог проверить» == «тишина есть». Раньше любая ошибка чтения
    # (нет прав у непривилегированного прогона) трактовалась как «тишины нет», и
    # код уходил в ветку РЕАЛЬНОЙ отправки — не улетало лишь потому, что токен
    # тоже недоступен. Защита не должна держаться на такой случайности.
    _mu = 0
    try:
        _mu = int(open("/var/lib/malware-watch/mute").read().strip() or 0)
    except FileNotFoundError:
        _mu = 0                      # тишина не ставилась вовсе — это известный факт
    except Exception as _e:          # прочитать НЕ СМОГЛИ — трактуем в пользу молчания
        try:
            with open("/var/log/bait-watch/events.jsonl", "a") as _f:
                _f.write(json.dumps({"event": "mute_unreadable", "severity": "WARN",
                                     "detail": str(_e)[:200], "ts": time.time(),
                                     "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%S+0000", time.gmtime())},
                                    ensure_ascii=False) + "\n")
        except Exception:
            pass
        return True, "muted (файл тишины не читается — молчим)"
    if _mu > time.time():
        try:
            with open("/var/log/malware-watch/muted.log", "a") as _f:
                _f.write("%s\tMUTED-bait\t%s\n" % (
                    time.strftime("%F %T", time.gmtime()), text.split("\n")[0][:160]))
        except Exception:
            pass
        return True, "muted"
    env = read_env_file(TG_ENV_FILE)
    token, chat = env.get("TG_TOKEN"), env.get("TG_CHAT")
    _wh = _webhook(env.get("ALERT_WEBHOOK_URL"), text)
    if not token or not chat:
        if _wh is None:
            return False, f"нет TG_TOKEN/TG_CHAT и ALERT_WEBHOOK_URL в {TG_ENV_FILE}"
        return bool(_wh), ("ok (webhook)" if _wh else "webhook failed")
    if len(text) > 4000:
        text = text[:3900] + "\n…(обрезано)"
    data = urllib.parse.urlencode({
        "chat_id": chat, "text": text, "parse_mode": "HTML",
        "disable_web_page_preview": "true"}).encode()
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{token}/sendMessage", data=data)
            with urllib.request.urlopen(req, timeout=15) as r:
                body = json.loads(r.read().decode())
                if body.get("ok"):
                    return True, "ok"
                return False, str(body)[:200]
        except Exception as e:
            if attempt == 2:
                return False, str(e)[:200]
            time.sleep(2)
    return False, "?"


def _webhook(url, text):
    """Optional JSON webhook (Slack/Discord/ntfy-style). None = not configured."""
    url = (url or os.environ.get("ALERT_WEBHOOK_URL") or "").strip()
    if not url:
        return None
    import urllib.request, html as _h
    plain = _h.unescape(re.sub(r"<[^>]*>", "", text))[:3800]
    req = urllib.request.Request(
        url, data=json.dumps({"text": plain, "content": plain}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15).read()
        return True
    except Exception:
        return False


def queue_amber(title, body, aid=""):
    """Положить некрасный факт в ОБЩУЮ очередь сторожа. → (ok, что вышло).

    Своей отправки тут нет вообще: дальше работают правила соседнего
    сторожа (отпечаток раз в сутки, бюджет, тихие часы, одна сводка).
    """
    if not os.path.exists(MW_SCRIPT):
        return False, f"нет {MW_SCRIPT}"
    try:
        r = subprocess.run([MW_SCRIPT, "queue-amber", title[:200], body[:1200],
                            (aid or "")[:16]],
                           capture_output=True, text=True, timeout=30)
        out = (r.stdout or r.stderr or "").strip()[:200]
        return r.returncode == 0, out or f"код возврата {r.returncode}"
    except Exception as e:
        return False, str(e)[:200]


def amber_body(rule, p, baits, sess):
    """Человеческий текст для общей сводки. Без тегов — его склеивают с чужими."""
    who = p.get("comm") or "?"
    cmd = (p.get("cmdline") or p.get("session_leader") or "").strip()
    where = p.get("where") or "?"
    frac, skipped, ndirs = sess.coverage()
    mb = sess.other_bytes / (1024 * 1024)
    pre = max([e["pre"] for e in sess.pid_ev.values()] or [0]) / (1024 * 1024)
    if rule == "walk":
        # обход мог перелопатить дерево ДО первой приманки — тогда «между
        # приманками» будет ноль, и без этой оговорки строка выглядит враньём
        vol = f"{mb:.0f} МБ обычных файлов между ними"
        if pre >= 1:
            vol += f" и ещё {pre:.0f} МБ до первой приманки"
        head = (f"Похоже на наш обычный поиск по папкам: программа {who} "
                f"прочитала подряд {sess.distinct} файлов-приманок в {ndirs} "
                f"папках, {vol}, пропустив рядом {skipped}.")
        tail = ("Так ходит рекурсивный поиск — он читает папку целиком. "
                "Если поиск сейчас никто не запускал, это тревога: "
                "смотри команду ниже.")
    else:
        head = (f"Программа {who} открыла файлов-приманок: {sess.distinct}. "
                f"Поведение не похоже ни на обход папок, ни на прицельный "
                f"сбор секретов.")
        tail = "Узнаёшь команду — можно не обращать внимания."
    return (f"{head}\n{tail}\nГде: {where}. Команда: {cmd[:200] or '(не успели снять)'}\n"
            f"Файлы: {', '.join(os.path.basename(b) for b in baits[:6])}"
            + (f" и ещё {len(baits) - 6}" if len(baits) > 6 else ""))


def esc(s):
    return html.escape(str(s), quote=False)


def build_alert(sev, p, baits, first_ts, why="", sess=None):
    icon = {"CRIT": "🚨", "WARN": "⚠️", "INFO": "ℹ️"}[sev]
    head = {"CRIT": "Незнакомая программа охотится за секретами",
            "WARN": "Приманки задело сплошным поиском по папкам",
            "INFO": "Приманку открыл известный процесс"}[sev]
    when = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(first_ts))

    out = [f"{icon} <b>{esc(head)}</b>",
           f"<i>{esc(when)} · {esc(p.get('where', '?'))}</i>", ""]

    out.append(f"🎣 <b>Что открыли ({len(baits)})</b>")
    shown = "\n".join(f"• <code>{esc(b)}</code>" for b in baits[:12])
    if len(baits) > 12:
        shown += f"\n• …и ещё {len(baits) - 12}"
    out += [f"<blockquote>{shown}</blockquote>", ""]

    out.append("👤 <b>Кто открыл</b>")
    who = [f"• программа: <b>{esc(p.get('comm', '?'))}</b> (номер {p.get('pid')})"]
    if p.get("cmdline"):
        who.append(f"• команда: <code>{esc(p['cmdline'][:300])}</code>")
    elif p.get("session_leader"):
        who.append(f"• запущено из: <code>{esc(p['session_leader'])}</code>")
    else:
        who.append("• команда: <i>процесс успел завершиться</i>")
    who.append(f"• файл программы: <code>{esc(p.get('exe', '?'))}</code>")
    who.append(f"• от чьего имени: uid {p.get('uid')}")
    if p.get("cwd") and p["cwd"] != "(недоступен)":
        who.append(f"• рабочая папка: <code>{esc(p['cwd'])}</code>")
    if p.get("parents"):
        who.append(f"• кто запустил: {esc(p['parents'])}")
    if p.get("connections"):
        who.append("• соединения: " + esc(", ".join(p["connections"])))
    out += [f"<blockquote>{chr(10).join(who)}</blockquote>"]

    if p.get("exe_deleted"):
        out += ["", "☠️ <b>Программа удалила свой файл с диска</b>",
                "<blockquote>Так прячется вредонос. Ровно этот приём был "
                "при взломе 25.07.</blockquote>"]

    if why:
        out += ["", "🧠 <b>Почему так решили</b>",
                f"<blockquote>{esc(why)}</blockquote>"]

    if sess is not None:
        mb = sess.other_bytes / (1024 * 1024)
        frac, skipped, ndirs = sess.coverage()
        lines = [f"• попутно прочитано обычных файлов: <b>{mb:.1f} МБ</b>",
                 f"• приманок задето: <b>{sess.distinct}</b> из "
                 f"{sum(len(v) for v in BAIT_SIBLINGS.values()) or 18}"
                 f", из них с ключами и паролями: <b>{len(sess.valuable())}</b>",
                 f"• папок затронуто: <b>{ndirs}</b>"]
        if skipped:
            lines.append(f"• в этих же папках <b>не тронуто {skipped}</b> "
                         f"таких же файлов (прочитано {frac:.0%} лежащего рядом) "
                         f"— значит, <b>выбирали</b>, а не читали подряд")
        else:
            lines.append("• в затронутых папках прочитано <b>всё подряд</b> — "
                         "похоже на обычный поиск")
        lines.append(f"• длилось: <b>{max(1, int(sess.last - sess.first))} сек</b>")
        out += ["", "📊 <b>Как оно читало</b>",
                "<blockquote>" + "\n".join(lines) + "</blockquote>"]

    if p.get("allow_rejected"):
        out += ["", "🎭 <b>Программа прикинулась доверенной</b>",
                "<blockquote>Она назвалась именем из списка разрешённых, но "
                f"проверку не прошла:\n{esc(p['allow_rejected'])}</blockquote>"]

    if sev == "CRIT":
        out += ["", "🔥 <b>Что это значит</b>",
                "<blockquote>• Эти файлы — <b>подделки</b>, настоящих паролей в "
                "них нет: их читают только если кто-то ищет секреты.\n"
                "• Программа выше <b>не входит в список известных</b> и лезла "
                "именно в секреты, а не просто шла по папкам.\n"
                "• Проверь по команде и папке выше, узнаёшь ли ты её. "
                "<b>Не узнаёшь — закрывай доступ.</b></blockquote>"]
    elif sev == "WARN":
        out += ["", "🙂 <b>Что это значит</b>",
                "<blockquote>• Скорее всего это <b>наш же поиск по папкам</b>: "
                "программа читала всё подряд, приманки попались заодно.\n"
                "• Одно письмо на весь такой проход, а не по письму на файл.\n"
                "• <b>Если такой поиск сейчас никто не запускал — это тревога</b>, "
                "смотри команду выше.</blockquote>"]

    out += ["", "<i>приманки · bait-watch</i>"]
    return "\n".join(out)


# ────────────────────────────── дедуп ─────────────────────────────────────
class Dedup:
    def __init__(self, path):
        self.path, self.map = path, {}
        try:
            with open(path) as f:
                self.map = json.load(f)
        except Exception:
            pass

    def should_send(self, key, now, window=DEDUP_SECONDS):
        if now - self.map.get(key, 0) >= window:
            self.map[key] = now
            self.save()
            return True
        return False

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.map, f)
            os.replace(tmp, self.path)
        except Exception:
            pass


def rule_of(sig):
    """Какое правило вынесло вердикт — из меток, которые кладёт decide()."""
    for token in sig or ():
        if str(token).startswith("rule:"):
            return str(token)[5:]
    return "?"


class DailyBudget:
    """Сколько сообщений класса уже ушло за последние сутки.

    Переживает перезапуск: иначе рестарт службы обнулял бы потолок, и
    «не больше N в сутки» держалось бы ровно до первой перезагрузки.
    """

    def __init__(self, path):
        self.path, self.map = path, {}
        try:
            with open(path) as f:
                self.map = json.load(f)
        except Exception:
            pass

    def _fresh(self, cls, now):
        keep = [t for t in self.map.get(cls, []) if now - t < 86400]
        self.map[cls] = keep
        return keep

    def used(self, cls, now):
        return len(self._fresh(cls, now))

    def take(self, cls, now, limit):
        """Забрать одно место в суточном лимите. False = потолок исчерпан."""
        keep = self._fresh(cls, now)
        if len(keep) >= limit:
            return False
        keep.append(now)
        self.save()
        return True

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.map, f)
            os.replace(tmp, self.path)
        except Exception:
            pass


# ─────────────── улика по сессии: обход дерева или прицельный сбор ────────
class Session:
    """Копит улики по ОДНОЙ сессии чтения приманок.

    Решение принимается не по имени программы (оно подделывается), а по форме
    поведения: обход каталога читает горы постороннего между приманками,
    прицельный сбор — почти ничего, кроме самих секретов.
    """

    def __init__(self, key, ts):
        self.key, self.first, self.last = key, ts, ts
        self.baits, self.shown = [], []
        self.other_bytes = self.other_syscr = 0
        self.io_unavailable = False
        # ⚠️ Улики считаем ПО КАЖДОМУ ПРОЦЕССУ отдельно, а не в общий котёл
        # сессии: иначе стилер, запущенный в том же ssh-логине, где до него
        # прошёл рекурсивный grep, унаследовал бы его «обход дерева» и
        # понизился до WARN. Склейка по сессии остаётся только для ПИСЬМА.
        self.pid_ev = {}           # pid → {other, syscr, baits, io}
        self.intent = []
        self.exe_deleted = False
        # ⚠️ Режим на момент САМОГО ЧТЕНИЯ, а не на момент отправки: тир
        # считается с задержкой (окно склейки), и к этому времени флаг тишины
        # самотеста уже снят — иначе самотест сам себе шлёт боевую тревогу.
        self.quiet_seen = False
        self.maint_seen = None
        self.proc = None
        self.alerted_sev = None
        self.alerted_ts = 0.0
        self.flushed_at = 0.0
        self.urgent = False
        # ⚠️ Вывод «это выборочная охота» имеет смысл только по ЗАКОНЧЕННОМУ
        # (замолчавшему) проходу: на середине рекурсивного обхода каталог
        # законно выглядит недочитанным. settled_done гарантирует, что сессию
        # ОБЯЗАТЕЛЬНО пересмотрят ещё раз после того, как она затихла, даже
        # если новых событий уже не было — иначе медленный вор, разбитый
        # принудительной отправкой по AGG_MAX, навсегда остался бы с WARN.
        self.settled_done = False

    def add(self, path, seen_as, p, ts, bait_size, quiet=False, maint=None):
        self.last = ts
        self.quiet_seen = self.quiet_seen or bool(quiet)
        self.maint_seen = self.maint_seen or maint
        if path not in self.baits:
            self.baits.append(path)
            self.shown.append(seen_as)
        pid = p.get("pid")
        ev = self.pid_ev.setdefault(pid, {"other": 0, "syscr": 0,
                                          "baits": set(), "io": None, "pre": 0})
        ev["baits"].add(path)
        rchar, syscr = p.get("rchar", -1), p.get("syscr", -1)
        if rchar < 0:
            self.io_unavailable = True
        else:
            prev = ev["io"]
            # ⚠️ Первое попадание процесса НЕ засчитываем как «посторонние
            # чтения»: до него интерпретатор успевает прочитать свою stdlib,
            # и любой стилер на python выглядел бы как обход дерева.
            # Считаем только то, что процесс прочитал МЕЖДУ приманками.
            if prev is None:
                # сколько процесс успел прочитать ДО того, как впервые задел
                # приманку: у обхода дерева это десятки МБ, у стилера — почти
                # ничего (см. PREWALK_BYTES)
                ev["pre"] = max(0, rchar - bait_size)
            if prev is not None:
                prev_r, prev_s, prev_bait = prev
                # снимок берётся в момент open(), т.е. содержимое ПРОШЛОЙ
                # приманки попало в интервал — его и вычитаем
                d_bytes = max(0, (rchar - prev_r) - prev_bait)
                d_syscr = max(0, (syscr - prev_s) - 2)
                ev["other"] += d_bytes
                ev["syscr"] += d_syscr
                self.other_bytes += d_bytes
                self.other_syscr += d_syscr
            ev["io"] = (rchar, syscr, bait_size)
        self.intent = self.intent or secret_intent(p)
        self.exe_deleted = self.exe_deleted or bool(p.get("exe_deleted"))
        # держим самый информативный снимок процесса
        if self.proc is None or (not self.proc.get("cmdline") and p.get("cmdline")):
            self.proc = p

    @property
    def distinct(self):
        return len(self.baits)

    def coverage(self):
        """Полнота обхода. → (доля покрытия, пропущено соседей, каталогов).

        Смотрим ТОЛЬКО каталоги, куда процесс заведомо заходил (он открыл там
        приманку). Рекурсивный поиск читает каталог целиком → доля 1.00.
        Вор берёт из каталога лишь то, что ему нужно → доля заметно ниже.
        Это метрика, которой он НЕ управляет объёмом читаемого мусора.
        """
        dirs = {}
        for b in self.baits:
            dirs.setdefault(os.path.dirname(b), set()).add(b)
        reach = set()
        for d in dirs:
            reach |= BAIT_SIBLINGS.get(d, set())
        hit = set(self.baits) & reach
        skipped = len(reach) - len(hit)
        frac = (len(hit) / len(reach)) if reach else 1.0
        return frac, skipped, len(dirs)

    def valuable(self):
        """Приманки с ключевым материалом (ключи, пароли, токены)."""
        return [b for b in self.baits if BAIT_VALUE_RE.search(b)]

    def hunting(self, settled):
        """Выборочная охота за секретами, замаскированная чтением мусора.

        Считается только по ЗАТИХШЕЙ сессии (settled): на середине обхода
        каталог законно недочитан. Вердикт НЕ зависит от объёма постороннего
        чтения — именно поэтому его нельзя размыть мусором.
        """
        if not settled:
            return None
        val = self.valuable()
        core = [b for b in self.baits if BAIT_CORE_RE.search(b)]
        frac, skipped, ndirs = self.coverage()
        # ⚠️ Нижняя граница. Две приманки — слишком слабая улика для громкого
        # класса: ровно столько задевает любой узкий инструмент, который
        # законно читает пару файлов настроек (замер 28.07: пять «2 из 2» за
        # день, все — наши же прогоны). Поэтому либо ТРИ разных файла, либо
        # два, но из ЯДРА — их вместе законно не читает никто.
        if len(self.baits) < HUNT_MIN_BAITS and len(core) < HUNT_MIN_CORE:
            return None
        if (len(val) >= HUNT_VALUABLE and skipped >= 1 and frac < HUNT_COVER
                and (ndirs >= HUNT_DIRS or skipped >= 2)):
            return (f"брали ВЫБОРОЧНО именно секреты: {len(val)} шт. из "
                    f"{ndirs} разных папок, а {skipped} приманок рядом, в тех же "
                    f"папках, не тронули (прочитано {frac:.0%} того, что лежало "
                    f"рядом). Сплошной поиск так не ходит — он читает папку "
                    f"целиком; объём попутного чтения тут ничего не меняет")
        return None

    def late_probe(self):
        """Досэмплировать /proc/<pid>/io перед отправкой: длинный обход дерева
        мог задеть приманки в самом начале, и до отправки успел прочитать ещё
        гору постороннего. Мёртвые процессы просто пропускаем."""
        for pid, ev in self.pid_ev.items():
            if not ev["io"]:
                continue
            rchar, syscr = read_io(pid)
            if rchar < 0:
                continue
            prev_r, prev_s, prev_bait = ev["io"]
            d_bytes = max(0, (rchar - prev_r) - prev_bait)
            d_syscr = max(0, (syscr - prev_s) - 2)
            ev["other"] += d_bytes
            ev["syscr"] += d_syscr
            self.other_bytes += d_bytes
            self.other_syscr += d_syscr
            ev["io"] = (rchar, syscr, 0)

    def shape(self):
        """'walk' — обход дерева, 'direct' — прицельный сбор, '?' — не ясно.

        Считается ПО ОТДЕЛЬНОМУ ПРОЦЕССУ: хватает одного процесса с формой
        прицельного сбора, чтобы вся сессия считалась сбором секретов.
        """
        walk = False
        for ev in self.pid_ev.values():
            n = len(ev["baits"])
            # ⚠️ «Прицельно» говорим ТОЛЬКО когда счётчики чтения реально
            # снялись. Если /proc/<pid>/io недоступен, нулевой «посторонний»
            # трафик — это незнание, а не улика: без этой проверки любой
            # процесс, у которого не читается io, выглядел бы стилером.
            # Ничего не теряем: незнакомый процесс всё равно уйдёт в CRIT
            # последней веткой, а проверенный — останется в белом списке.
            if (ev["io"] is not None and n >= SWEEP_COUNT
                    and ev["other"] < DIRECT_BYTES
                    and ev["syscr"] < DIRECT_SYSCR
                    and ev["pre"] < PREWALK_BYTES):
                return "direct"
            if (ev["other"] >= WALK_BYTES or ev["syscr"] >= WALK_SYSCR
                    or ev["pre"] >= PREWALK_BYTES):
                walk = True
        if walk:
            return "walk"
        # несколько приманок за сессию, и ни один процесс не читал ничего
        # постороннего — это тоже прицельный сбор (стилер вида `cat` в цикле,
        # где на каждый файл свой процесс)
        if (self.distinct >= SWEEP_COUNT and not self.io_unavailable
                and self.other_bytes < DIRECT_BYTES
                and self.other_syscr < DIRECT_SYSCR
                and max([e["pre"] for e in self.pid_ev.values()] or [0])
                    < PREWALK_BYTES):
            return "direct"
        return "?"

    def decide(self, allowed, owner_only, quiet, maint, settled=False):
        """Итоговый тир по накопленным уликам. Считается НА МОМЕНТ ОТПРАВКИ,
        а не по первому событию — иначе прочёс успевает получить CRIT раньше,
        чем станет видно, что это обычный обход каталога."""
        quiet = quiet or self.quiet_seen
        maint = maint or self.maint_seen
        shape = self.shape()
        frac, skipped, ndirs = self.coverage()
        why, sig = "", [f"форма={shape}",
                        f"постороннего={self.other_bytes // 1024} КБ/"
                        f"{self.other_syscr} чтений",
                        f"приманок={self.distinct}",
                        f"ценных={len(self.valuable())}",
                        f"покрытие={frac:.2f}",
                        f"пропущено_рядом={skipped}",
                        f"каталогов={ndirs}",
                        f"затихла={int(bool(settled))}"]
        if self.exe_deleted:
            return "CRIT", "программа удалила свой файл с диска", sig + ["rule:deleted"]
        # ⚠️ Слова в командной строке САМИ ПО СЕБЕ уликой больше не считаются.
        # Замер 28.07: все срабатывания «в команде ищут секреты» за день — наши
        # собственные руки (`ssh-keygen -lf id_rsa`, `ssh -i …/id_rsa`,
        # `grep -rl token …`): либо одна приманка, либо сплошной обход папок.
        # Громким это остаётся, только когда со словами совпало и ПОВЕДЕНИЕ —
        # такие случаи ниже уже поймают direct/hunt, а сюда доходит остаток.
        if self.intent and self.distinct >= 2 and self.shape() != "walk":
            return "CRIT", ("в самой команде ищут секреты: "
                            + ", ".join(self.intent)), sig + ["rule:intent"]
        # Разрешение, привязанное к ПОЛНОМУ ПУТИ бинаря (`exe:`) и проверенное
        # по владельцу/каталогу/пакету, — единственное, что стоит выше разбора
        # формы чтения. Иначе наш же индексатор файлов, который штатно читает
        # подряд несколько приманок и почти ничего кроме них, каждый раз ловил
        # бы CRIT «прицельный сбор» — ровно тот ночной шум, из-за которого весь
        # разбор и переделывали. Разрешение по ИМЕНИ (comm:/cmdline:) такого
        # веса не имеет и проверяется ниже.
        if allowed == "exe":
            return "INFO", "процесс в белом списке (проверенный бинарь)", \
                   sig + ["rule:allow_exe"]
        if shape == "direct" and self.distinct >= SWEEP_COUNT:
            return "CRIT", ("читает ТОЛЬКО файлы-секреты, ничего постороннего "
                            "рядом не открывает"), sig + ["rule:direct"]
        if allowed:
            return "INFO", "процесс в белом списке", sig + ["rule:allow_name"]
        if owner_only:
            return "INFO", "программа открыла свой же файл настроек", sig + ["rule:owner"]
        # ⚠️ Выборочная охота стоит ПОСЛЕ белого списка и «своего конфига», но
        # ПЕРЕД разбором формы чтения. Почему именно тут:
        #   • после белого списка — иначе индексатор dev-инструмента (проверенный
        #     бинарь, покрытие 0.56) сыпал бы CRIT: он тоже читает выборочно;
        #   • после «своего конфига» — иначе `git push`, читающий .netrc и
        #     .git-credentials, выглядел бы охотой (2 ценных, покрытие 0.40);
        #   • перед формой и окном обслуживания — чтобы мусор и объявленное
        #     обслуживание НЕ могли опустить вердикт ниже громкого.
        hunt = self.hunting(settled)
        if hunt:
            return "CRIT", hunt, sig + ["rule:hunt"]
        if self.intent:
            # слова есть, а поведение обычное — в общую сводку, не в звонок
            return "WARN", ("в команде есть слова про секреты ("
                            + ", ".join(self.intent) + "), но читали как "
                            "обычный инструмент"), sig + ["rule:intent_soft"]
        if quiet:
            # самотест не будит оператора, но в журнал событие идёт
            return "INFO", "режим тишины (самотест)", sig + ["rule:quiet"]
        if shape == "walk":
            if maint:
                return "INFO", ("обход каталога в объявленном окне обслуживания: "
                                + str(maint.get("reason", ""))[:120]), sig + ["rule:maint"]
            return "WARN", ("похоже на сплошной обход каталога: между приманками "
                            "программа прочитала гору обычных файлов"), sig + ["rule:walk"]
        return "CRIT", "программа не из известных, поведение непонятное", sig + ["rule:unknown"]


# ────────────────────────────── демон ─────────────────────────────────────
class BaitWatcher:
    def __init__(self):
        self.baits = load_list(BAITS_LIST)
        self.allow = set(load_list(ALLOW_LIST))
        self.dedup = Dedup(os.path.join(STATE_DIR, "dedup.json"))
        self.budget = DailyBudget(os.path.join(STATE_DIR, "daily.json"))
        self.fan, self.perm_mode = None, False
        self.by_inode, self.marked = {}, []
        self.q = queue.Queue(maxsize=10000)
        # отправка в Telegram идёт ОТДЕЛЬНЫМ потоком: один sendMessage занимает
        # ~7 с, и если слать прямо из агрегатора, окно склейки истекает между
        # событиями — прочёс из 8 файлов разъезжается на 8 отдельных тревог.
        self.sendq = queue.Queue(maxsize=1000)
        self.sessions = {}      # ключ сессии → Session (улики + буфер тревоги)
        self.bait_size = {}     # путь приманки → размер, чтобы вычесть из rchar
        self.sent_times, self.throttle_notified = deque(), 0.0
        self._allow_logged = set()   # чтобы отказ белого списка не спамил журнал
        self.self_pid = os.getpid()
        self.stop = threading.Event()

    # ── постановка меток ──
    def setup(self):
        if not self.baits:
            print(f"[err] пустой список приманок {BAITS_LIST}", file=sys.stderr)
            sys.exit(1)
        load_geography(self.baits)   # каталог → соседи, для проверки полноты обхода
        try:
            self.fan = fanotify_init(
                FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
                O_RDONLY | O_LARGEFILE | O_CLOEXEC)
            self.perm_mode = True
        except OSError as e:
            print(f"[warn] режим PERM недоступен ({e.strerror}), "
                  f"откат в режим наблюдения", file=sys.stderr)
            self.fan = fanotify_init(
                FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK,
                O_RDONLY | O_LARGEFILE | O_CLOEXEC)
            self.perm_mode = False

        mask = FAN_OPEN_PERM if self.perm_mode else (FAN_OPEN | FAN_ACCESS)
        failed = []
        for b in self.baits:
            try:
                fanotify_mark(self.fan, FAN_MARK_ADD, mask, b)
                st = os.stat(b)
                # путь в событии приходит в mount-namespace ТОГО, КТО ЧИТАЛ
                # (из контейнера это /home/user/...), поэтому сопоставляем по inode
                self.by_inode[(st.st_dev, st.st_ino)] = b
                self.bait_size[b] = st.st_size
                self.marked.append(b)
            except OSError as e:
                failed.append(f"{b}: {e.strerror}")
        log_line({"event": "startup", "marked": len(self.marked),
                  "failed": failed, "pid": self.self_pid,
                  "mode": "PERM" if self.perm_mode else "NOTIFY"})
        print(f"[ok] под наблюдением приманок: {len(self.marked)} "
              f"(режим {'PERM' if self.perm_mode else 'NOTIFY'})")
        for f in failed:
            print(f"[warn] не смог пометить {f}", file=sys.stderr)

    # ── быстрый путь: читаем события, отвечаем ALLOW, кладём в очередь ──
    def reader_loop(self):
        poller = select.poll()
        poller.register(self.fan, select.POLLIN)
        while not self.stop.is_set():
            try:
                if not poller.poll(1000):
                    continue
                buf = os.read(self.fan, 65536)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EINTR):
                    continue
                raise
            off = 0
            while off + METADATA_LEN <= len(buf):
                elen, _vers, _res, _mlen, mask, efd, epid = struct.unpack_from(
                    METADATA_FMT, buf, off)
                if elen < METADATA_LEN or off + elen > len(buf):
                    break
                off += elen
                if efd < 0:
                    continue
                try:
                    info = None
                    if epid != self.self_pid:
                        try:
                            seen_as = os.readlink(f"/proc/self/fd/{efd}")
                        except OSError:
                            seen_as = "(неизвестно)"
                        try:
                            st = os.fstat(efd)
                            path = self.by_inode.get((st.st_dev, st.st_ino), seen_as)
                        except OSError:
                            path = seen_as
                        info = (path, seen_as, fast_forensics(epid),
                                mask, time.time())
                finally:
                    # ⚠️ ОТВЕЧАЕМ ВСЕГДА и ПЕРВЫМ ДЕЛОМ — иначе открывающий
                    # процесс останется висеть. Ничего не блокируем.
                    if self.perm_mode:
                        try:
                            os.write(self.fan, struct.pack(
                                RESPONSE_FMT, efd, FAN_ALLOW))
                        except Exception:
                            pass
                    try:
                        os.close(efd)
                    except Exception:
                        pass
                if info:
                    try:
                        self.q.put_nowait(info)
                    except queue.Full:
                        pass

    # ── медленный путь ──
    def is_allowed(self, p):
        """Белый список. → "exe" | "name" | None.

        ⚠️ Совпадения ИМЕНИ мало (дыра D, 28.07): comm и командная строка
        подделываются одним prctl(), поэтому запись срабатывает только если в
        порядке и происхождение бинаря. Отказ пишем в журнал — по нему видно
        попытку прикинуться доверенным инструментом.

        ⚠️ Полное доверие ("exe") даёт только НАШ файл. Проверено 28.07: копия
        разрешённого бинаря `…/some-cli/bin/some-cli.exe` лежит ВНУТРИ
        рабочих контейнеров по тому же пути и тоже принадлежит root, но это
        другой файл (другое устройство, другой inode, другой размер) — и в
        журнале уже есть чтение приманки такой копией. Ей выдаём урезанное
        доверие "name": тихо, пока поведение обычное, но прицельный сбор и
        выборочную охоту она больше не прячет.
        """
        if p["pid"] == self.self_pid:
            return "exe"
        for pat in self.allow:
            by_name = None
            if pat.startswith("exe:") and p.get("exe") == pat[4:]:
                by_name = False          # путь бинаря — самый крепкий якорь
            elif pat.startswith("comm:") and p.get("comm") == pat[5:]:
                by_name = True
            elif pat.startswith("cmdline:") and pat[8:] in (p.get("cmdline") or ""):
                by_name = True
            if by_name is None:
                continue
            lvl, why = comm_trusted(p) if by_name else exe_origin(p)
            if lvl == "weak":
                p["allow_weak"] = f"{pat} → {why}"
                lvl = "name"          # инструмент узнан, но файл не наш
            if lvl:
                p["allow_by"] = pat
                return lvl
            p["allow_rejected"] = f"{pat} → {why}"
            if p.get("pid") not in self._allow_logged:
                self._allow_logged.add(p["pid"])
                if len(self._allow_logged) > 2000:
                    self._allow_logged.clear()
                log_line({"event": "allow_rejected", "pattern": pat,
                          "reason": why, "pid": p.get("pid"),
                          "comm": p.get("comm"), "exe": p.get("exe"),
                          "where": p.get("where"),
                          "cmdline": p.get("cmdline", "")[:200]})
        return None

    def owner_only(self, s):
        """Все приманки сессии — собственные конфиги читающей программы."""
        exe = (s.proc or {}).get("exe", "")
        return bool(s.baits) and all(owned_config(exe, b) for b in s.baits)

    def handle(self, path, seen_as, p, mask, ts):
        enrich(p)
        allowed = self.is_allowed(p)

        # ключ прочёса — СЕССИЯ; для уже мёртвых процессов без сессии всё
        # сваливаем в один общий бак, чтобы всплеск не разъехался на N тревог
        skey = p.get("session") or (f"dead" if not p["alive"] else p["pid"])
        key = f"sess{skey}"

        s = self.sessions.get(key)
        if s is None or ts - s.last > SWEEP_WINDOW:
            s = self.sessions[key] = Session(key, ts)
        quiet, maint = quiet_active(), maint_active()
        s.add(path, seen_as, p, ts, self.bait_size.get(path, 0), quiet, maint)

        # settled=False: по одному событию нельзя судить о полноте обхода —
        # вердикт «выборочная охота» выносится только по затихшей сессии.
        sev, why, sig = s.decide(allowed, self.owner_only(s), quiet, maint)
        frac, skipped, ndirs = s.coverage()

        log_line({"event": "bait_read", "severity": sev, "bait": path,
                  "seen_as": seen_as, "mask": mask, "proc": p,
                  "distinct_baits": s.distinct, "allowlisted": allowed,
                  "quiet": quiet, "maint": bool(maint), "sweep_key": str(skey),
                  "shape": s.shape(), "reason": why, "signals": sig,
                  "other_bytes": s.other_bytes, "other_syscr": s.other_syscr,
                  "coverage": round(frac, 2), "skipped_siblings": skipped,
                  "bait_dirs": ndirs, "valuable": len(s.valuable()),
                  "allow_level": allowed, "allow_by": p.get("allow_by"),
                  "allow_weak": p.get("allow_weak"),
                  "allow_rejected": p.get("allow_rejected")})

        # прицельный сбор и стёртый с диска бинарь не ждут окна склейки
        if sev == "CRIT" and (s.intent or s.exe_deleted):
            s.urgent = True

    def rate_ok(self, now):
        while self.sent_times and now - self.sent_times[0] > 3600:
            self.sent_times.popleft()
        if len(self.sent_times) < MAX_ALERTS_PER_HOUR:
            self.sent_times.append(now)
            return True
        if now - self.throttle_notified > 3600:
            self.throttle_notified = now
            tg_send("🔇 <b>Слишком много тревог по приманкам</b>\n<blockquote>"
                    f"За час больше {MAX_ALERTS_PER_HOUR} сообщений — дальше "
                    "молчу, чтобы не залить чат.\nВсё пишется в журнал: "
                    "<code>/var/log/bait-watch/events.jsonl</code></blockquote>")
        return False

    def cap_notice(self, rule, now):
        """Один раз в сутки сказать, что потолок выбран и дальше тихо.

        Само уведомление тоже идёт через суточный дедуп — иначе «молчу»
        превратилось бы в новый источник шума. Одно на всю ловушку, а не
        на каждое правило: иначе шесть правил дадут шесть «я молчу».
        """
        if not self.dedup.should_send("cap-notice", now, window=SIG_TTL):
            return
        try:
            self.sendq.put_nowait({
                "mode": "tg", "severity": "CRIT", "baits": [], "pid": 0,
                "comm": "cap", "rule": "cap", "signals": ["rule:cap"],
                "why": f"суточный потолок ({rule})",
                "text":
                "🔇 <b>Ловушка: суточный предел сообщений выбран</b>\n"
                "<blockquote>Тревог за сутки уже столько, сколько условлено — "
                "дальше молчу до завтра, чтобы не залить чат.\n"
                "Ловушка при этом работает: всё пишется в журнал, сводка за "
                "сутки — <code>bait-watch.py --digest</code>.</blockquote>"})
        except queue.Full:
            pass

    def flush_pending(self, force=False):
        """Одна сессия — одна тревога. Продолжение того же прочёса дописывается
        в журнал и повторным письмом не идёт; пробивает только эскалация."""
        now = time.time()
        rank = {"INFO": 0, "WARN": 1, "CRIT": 2}
        for key in list(self.sessions):
            s = self.sessions[key]
            # сессию выкидываем, когда она давно молчит
            if now - s.last > SWEEP_WINDOW and not force:
                del self.sessions[key]
                continue
            # сессия «затихла» — проход закончился (или надолго встал), и
            # только теперь имеет смысл судить о ПОЛНОТЕ обхода
            settled = force or (now - s.last >= AGG_QUIET)
            # с прошлого разбора новых событий не было — не пережёвываем заново.
            # ⚠️ Исключение: сессию, отправленную ДО того как затихла (по
            # s.urgent или по потолку AGG_MAX), обязаны пересмотреть ещё раз,
            # когда она затихнет: иначе медленный вор навсегда остаётся с тем
            # мягким тиром, который успел получить на середине.
            if s.last <= s.flushed_at and (s.settled_done or not settled):
                continue
            ripe = force or s.urgent or settled or (now - s.first >= AGG_MAX)
            if not ripe:
                continue
            s.flushed_at = now
            s.settled_done = s.settled_done or settled
            s.late_probe()      # добрать улики по всё ещё живому обходчику
            p = s.proc or {}
            sev, why, sig = s.decide(self.is_allowed(p), self.owner_only(s),
                                     quiet_active(), maint_active(), settled)
            s.urgent = False
            if sev not in ("CRIT", "WARN"):
                s.alerted_sev = s.alerted_sev or sev   # INFO — только журнал
                continue
            rule = rule_of(sig)
            # уже писали по этой сессии и тир не вырос — молчим
            if s.alerted_sev and rank[sev] <= rank[s.alerted_sev]:
                log_line({"event": "alert_suppressed", "reason": "session_sticky",
                          "key": key, "severity": sev, "baits": s.baits})
                continue
            # НЕ кража — своим сообщением не идёт вообще. Отдаём в общую
            # очередь сторожа: там свой отпечаток раз в сутки, общий бюджет
            # и одна утренняя сводка на всех.
            if rule in AMBER_RULES:
                s.alerted_sev = sev
                if not self.dedup.should_send(f"amber:{rule}", now,
                                              window=AMBER_CALL_GAP):
                    log_line({"event": "alert_suppressed", "reason": "amber_gap",
                              "rule": rule, "severity": sev, "baits": s.baits})
                    continue
                aid = hashlib.sha1(
                    f"{rule}|{p.get('exe') or p.get('comm')}".encode()
                ).hexdigest()[:10]
                try:
                    self.sendq.put_nowait({
                        "mode": "amber", "rule": rule, "severity": sev,
                        "title": AMBER_TITLE.get(rule, "Задета приманка"),
                        "body": amber_body(rule, p, s.shown or s.baits, s),
                        "aid": aid, "baits": list(s.baits), "why": why,
                        "pid": p.get("pid"), "comm": p.get("comm")})
                except queue.Full:
                    log_line({"event": "alert_dropped", "reason": "send_queue_full",
                              "severity": sev, "baits": s.baits})
                continue
            # ПОДПИСЬ = правило + программа + набор приманок, окно сутки.
            # Программа, которая лезет в приманки весь день, даёт ОДНО
            # сообщение, а не сорок.
            sigk = hashlib.sha1("|".join(sorted(s.baits)).encode()).hexdigest()[:10]
            prog = p.get("exe") or p.get("comm") or "?"
            dkey = f"{rule}|{prog}|{sigk}"
            if not self.dedup.should_send(dkey, now, window=SIG_TTL):
                s.alerted_sev = sev
                log_line({"event": "alert_suppressed", "reason": "signature_24h",
                          "key": dkey, "severity": sev, "baits": s.baits})
                continue
            # Кража в процессе идёт ПОВЕРХ общего предохранителя и не тратит
            # его: иначе шумные классы выбирают предел за день, и настоящий
            # вор приходит уже в заглушённую ловушку.
            steal = rule in BREAKTHROUGH
            over = self.budget.used("ВСЕГО", now) >= DAILY_MAX_TOTAL
            if (not steal and over) or not self.budget.take(rule, now,
                                                            DAILY_MAX[rule]):
                log_line({"event": "alert_suppressed", "reason": "daily_cap",
                          "key": dkey, "severity": sev, "rule": rule,
                          "baits": s.baits, "limit": DAILY_MAX[rule],
                          "breakthrough": steal,
                          "used_total": self.budget.used("ВСЕГО", now)})
                self.cap_notice(rule, now)
                continue
            if not steal:
                self.budget.take("ВСЕГО", now, DAILY_MAX_TOTAL)
            if not self.rate_ok(now):
                log_line({"event": "alert_suppressed", "reason": "rate_limit",
                          "key": dkey, "severity": sev, "baits": s.baits})
                continue
            s.alerted_sev, s.alerted_ts = sev, now
            text = build_alert(sev, p, s.shown or s.baits, s.first, why, s)
            try:
                self.sendq.put_nowait({
                    "mode": "tg", "text": text, "severity": sev,
                    "baits": list(s.baits), "pid": p.get("pid"),
                    "comm": p.get("comm"), "why": why, "signals": sig,
                    "rule": rule})
            except queue.Full:
                log_line({"event": "alert_dropped", "reason": "send_queue_full",
                          "severity": sev, "baits": s.baits})

    def sender_loop(self):
        """Единственное место, где мы ходим в сеть. Не тормозит агрегацию."""
        while not self.stop.is_set() or not self.sendq.empty():
            try:
                item = self.sendq.get(timeout=1.0)
            except queue.Empty:
                continue
            sev, baits = item.get("severity"), item.get("baits") or []
            if item.get("mode") == "amber":
                # НЕ отправка: кладём факт в общую очередь соседнего сторожа
                ok, info = queue_amber(item["title"], item["body"],
                                       item.get("aid", ""))
                log_line({"event": "queued_amber", "severity": sev, "ok": ok,
                          "detail": info, "rule": item.get("rule"),
                          "title": item["title"], "baits": baits,
                          "pid": item.get("pid"), "reason": item.get("why")})
                print(f"[{sev}] {item.get('rule')} → общая очередь сводки: "
                      f"{ok} {info}", flush=True)
                continue
            ok, info = tg_send(item["text"])
            # ⚠️ Причину пишем ИМЕННО ЗДЕСЬ: тир считается заново на момент
            # отправки, и без этого в журнале остаётся только промежуточный
            # вердикт по отдельным событиям — по нему потом не разберёшь,
            # за что именно ушла тревога.
            log_line({"event": "alert_sent", "severity": sev, "ok": ok,
                      "detail": info, "baits": baits, "pid": item.get("pid"),
                      "reason": item.get("why"), "signals": item.get("signals")})
            print(f"[{sev}] тревога по {len(baits)} приманкам "
                  f"({item.get('comm')}/{item.get('pid')}) → telegram={ok} {info}",
                  flush=True)

    def worker_loop(self):
        while not self.stop.is_set():
            try:
                item = self.q.get(timeout=1.0)
            except queue.Empty:
                item = None
            if item:
                try:
                    self.handle(*item)
                except Exception as e:
                    log_line({"event": "handler_error", "error": str(e)})
            self.flush_pending()
            if len(self.sessions) > 500:
                self.sessions.clear()
        self.flush_pending(force=True)

    def run(self):
        self.setup()
        signal.signal(signal.SIGTERM, lambda *a: self.stop.set())
        signal.signal(signal.SIGINT, lambda *a: self.stop.set())
        w = threading.Thread(target=self.worker_loop, daemon=True)
        s = threading.Thread(target=self.sender_loop, daemon=True)
        w.start(); s.start()
        try:
            self.reader_loop()
        finally:
            self.stop.set()
            w.join(timeout=30)   # доагрегирует и положит остатки в очередь отправки
            s.join(timeout=60)   # дошлёт всё, что накопилось
            log_line({"event": "shutdown"})


# ────────────────────────────── режимы CLI ────────────────────────────────
def cmd_status():
    baits = load_list(BAITS_LIST)
    print(f"приманок в списке: {len(baits)}")
    missing = 0
    for b in baits:
        ok = os.path.exists(b)
        missing += 0 if ok else 1
        print(f"  [{'OK ' if ok else 'НЕТ'}] {b}")
    if missing:
        print(f"\n⚠️ отсутствуют: {missing}")
    r = subprocess.run(["systemctl", "is-active", "bait-watch.service"],
                       capture_output=True, text=True)
    print(f"\nюнит bait-watch.service: {r.stdout.strip()}")
    m = maint_active()
    print(f"режим обслуживания: "
          + (f"ВКЛ ещё {m['left']} с — {m.get('reason', '')}" if m else "выкл"))
    try:
        with open(EVENTS_LOG) as f:
            last = [json.loads(l) for l in f if l.strip()][-1]
        print(f"последнее событие: {last.get('ts_iso')} {last.get('event')}")
    except Exception:
        pass
    return 0


def cmd_selftest():
    """Читаем приманку и убеждаемся, что тревога реально ушла в Telegram."""
    baits = load_list(BAITS_LIST)
    target = None
    for pref in ("/.aws/credentials", "/.npmrc", "/passphrase.txt"):
        target = next((b for b in baits if b.endswith(pref) and os.path.exists(b)),
                      None)
        if target:
            break
    target = target or next((b for b in baits if os.path.exists(b)), None)
    if not target:
        print("НЕТ ПРИМАНОК — самотест невозможен")
        return 2

    # сбрасываем дедуп по этой приманке, иначе повторный самотест «промолчит»
    dpath = os.path.join(STATE_DIR, "dedup.json")
    try:
        with open(dpath) as f:
            dmap = json.load(f)
        with open(dpath, "w") as f:
            json.dump({k: v for k, v in dmap.items() if target not in k}, f)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"  (не смог сбросить дедуп: {e})")

    # РЕЖИМ ТИШИНЫ: самотест не должен будить оператора. Событие попадёт в журнал,
    # но в Telegram не уйдёт. Флаг снимаем в finally — иначе ловушка ослепнет.
    start = time.time()
    try:
        with open(QUIET_FLAG, "w") as f:
            f.write(f"selftest pid={os.getpid()} ts={int(start)}\n")
    except Exception as e:
        print(f"⚠️ не смог включить режим тишины ({e}) — прерываю, "
              f"чтобы не поднимать ложную тревогу")
        return 2
    try:
        print(f"[1/3] читаю приманку: {target}  (режим тишины включён)")
        with open(target, "rb") as f:
            f.read(64)
        print("[2/3] жду появления записи в журнале (до 30 с)…")
        time.sleep(12)
    finally:
        try:
            os.unlink(QUIET_FLAG)
        except Exception:
            pass

    seen_read = seen_alert = None
    # ⚠️ Ждём ДОЛЬШЕ окна склейки: тревога отправляется не в момент чтения, а
    # через AGG_QUIET секунд тишины. Раньше самотест выходил сразу, как увидел
    # чтение, и не замечал ушедшего следом сообщения — ложное «ОК».
    deadline = start + AGG_QUIET + 25
    while time.time() < deadline:
        try:
            with open(EVENTS_LOG) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if e.get("ts", 0) < start - 1:
                        continue
                    if e.get("event") == "bait_read" and e.get("bait") == target:
                        seen_read = e
                    if e.get("event") == "alert_sent" and target in e.get("baits", []):
                        seen_alert = e
        except FileNotFoundError:
            pass
        time.sleep(2)

    print("[3/3] результат:")
    print(f"  чтение поймано и записано в журнал: {'ДА' if seen_read else 'НЕТ'}")
    if seen_read:
        pr = seen_read["proc"]
        print(f"    кто: {pr['comm']}/{pr['pid']} uid={pr['uid']} "
              f"где={pr.get('where')} severity={seen_read['severity']} "
              f"тишина={seen_read.get('quiet')}")
        print(f"    команда: {pr.get('cmdline', '')[:120]}")
    print(f"  сообщение в Telegram: {'УШЛО ⚠️' if seen_alert else 'не отправлено'}"
          f"  (в режиме тишины его быть НЕ должно)")

    ok = bool(seen_read) and seen_alert is None
    print()
    print("  ИТОГ: " + ("ОК — ловушка видит чтение, но оператора не будит"
                        if ok else
                        "ПРОБЛЕМА — см. /var/log/bait-watch/events.jsonl"))
    print("  (доставку в Telegram проверять отдельно: --test-tg)")
    return 0 if ok else 1


def cmd_maint(argv):
    """Объявить окно планового обслуживания (широкий поиск нашим инструментом).

        bait-watch.py --maint 600 "поиск домена по /srv/projects"
        bait-watch.py --maint-off

    Понижает ТОЛЬКО класс «сплошной обход каталога» до записи в журнал.
    Прицельный сбор секретов, поиск по словам вроде token/secret и программа
    с удалённым бинарём пробивают это окно и всё равно дают CRIT.
    """
    if os.geteuid() != 0:
        print("нужен root: /run пишет только он")
        return 2
    ttl = 600
    reason = "не указана"
    if argv:
        try:
            ttl = int(argv[0]); argv = argv[1:]
        except ValueError:
            pass
    if argv:
        reason = " ".join(argv)[:200]
    ttl = max(30, min(ttl, MAINT_MAX_AGE))
    with open(MAINT_FLAG, "w") as f:
        json.dump({"ttl": ttl, "reason": reason, "by": os.environ.get("SUDO_USER")
                   or "root", "pid": os.getppid()}, f, ensure_ascii=False)
    os.chmod(MAINT_FLAG, 0o644)
    log_line({"event": "maint_on", "ttl": ttl, "reason": reason,
              "by": os.environ.get("SUDO_USER") or "root"})
    print(f"режим обслуживания включён на {ttl} с: {reason}")
    print("прицельный сбор секретов он НЕ прячет — только сплошной обход папок")
    return 0


def cmd_maint_off():
    try:
        os.unlink(MAINT_FLAG)
        log_line({"event": "maint_off"})
        print("режим обслуживания снят")
    except FileNotFoundError:
        print("режим обслуживания и так выключен")
    except PermissionError:
        print("нужен root")
        return 2
    return 0


def cmd_digest(argv):
    """Сводка за сутки: что ловушка видела и о чём СОЗНАТЕЛЬНО промолчала.

        bait-watch.py --digest [часов]

    ⚠️ Ничего не отправляет — только печатает. Классы с нулевым суточным
    лимитом (сплошной обход каталога) видны ТОЛЬКО здесь, поэтому сводку
    надо включить в утреннее сообщение.
    """
    hours = 24
    if argv:
        try:
            hours = max(1, min(int(argv[0]), 168))
        except ValueError:
            pass
    cut = time.time() - hours * 3600
    reads = 0
    by_rule = defaultdict(lambda: {"n": 0, "progs": set(), "baits": set(),
                                   "sev": "INFO"})
    sent, suppressed = [], defaultdict(int)
    try:
        with open(EVENTS_LOG) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("ts", 0) < cut:
                    continue
                ev = e.get("event")
                if ev == "bait_read":
                    reads += 1
                    r = rule_of(e.get("signals") or [])
                    d = by_rule[r]
                    d["n"] += 1
                    d["sev"] = e.get("severity", d["sev"])
                    pr = e.get("proc") or {}
                    d["progs"].add(pr.get("comm") or "?")
                    d["baits"].add(os.path.basename(e.get("bait", "")))
                elif ev == "alert_sent":
                    sent.append(e)
                elif ev == "alert_suppressed":
                    suppressed[e.get("reason", "?")] += 1
    except FileNotFoundError:
        print("журнала ещё нет")
        return 0

    print(f"🎣 Ловушка на приманки — сводка за {hours} ч")
    print(f"   чтений приманок: {reads}")
    print(f"   отправлено сообщений: {len(sent)}"
          + (f" (из них заглушено тихим режимом: "
             f"{sum(1 for e in sent if e.get('detail') == 'muted')})" if sent else ""))
    print()
    if by_rule:
        print("   по правилам:")
        for r, d in sorted(by_rule.items(), key=lambda kv: -kv[1]["n"]):
            quiet = (" [в общую сводку сторожа]" if r in AMBER_RULES
                     else "" if DAILY_MAX.get(r, 0) > 0 else " [только журнал]")
            print(f"     {r:<11} {d['n']:>4} чтений · {d['sev']}{quiet}"
                  f" · программы: {', '.join(sorted(d['progs'])[:4])}")
    if suppressed:
        print()
        print("   промолчали намеренно:")
        for r, n in sorted(suppressed.items(), key=lambda kv: -kv[1]):
            print(f"     {r:<15} {n}")
    if sent:
        print()
        print("   что уходило:")
        for e in sent[-10:]:
            print(f"     {e['ts_iso'][11:19]} {e['severity']:<4} "
                  f"{(e.get('reason') or '')[:80]}")
    b = DailyBudget(os.path.join(STATE_DIR, "daily.json"))
    now = time.time()
    print()
    print("   суточные потолки по правилам: " + ", ".join(
        f"{k}={b.used(k, now)}/{v}"
        + ("(тихое)" if v <= 0 else "(поверх общего)" if k in BREAKTHROUGH else "")
        for k, v in DAILY_MAX.items())
        + f"; общий предохранитель (шумные классы)="
          f"{b.used('ВСЕГО', now)}/{DAILY_MAX_TOTAL}")
    return 0


def cmd_test_tg():
    ok, info = tg_send("🧪 <b>Проверка связи</b>\n<blockquote>Система ловушек "
                       "на секреты подключена к этому боту.</blockquote>")
    print(f"telegram: ok={ok} {info}")
    return 0 if ok else 1


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "--daemon"
    if arg == "--status":
        return cmd_status()
    if arg == "--selftest":
        return cmd_selftest()
    if arg == "--test-tg":
        return cmd_test_tg()
    if arg == "--digest":
        return cmd_digest(sys.argv[2:])
    if arg == "--maint":
        return cmd_maint(sys.argv[2:])
    if arg == "--maint-off":
        return cmd_maint_off()
    if arg == "--daemon":
        os.makedirs(LOG_DIR, exist_ok=True)
        os.makedirs(STATE_DIR, exist_ok=True)
        BaitWatcher().run()
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
