#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit-bridge — потребитель журнала auditd.

ЗАЧЕМ. auditd писал 460-855 МБ/сутки, которые НИКТО не читал: 0 активных
плагинов audispd, в malware-watch.sh слово "audit" встречается 0 раз.
Этот скрипт — недостающий потребитель. Он НЕ добавляет правил и НЕ создаёт
нагрузки на ядро: читает то, что уже пишется.

ЗОНА ОТВЕТСТВЕННОСТИ. Свой файл, свой стейт, свой юнит. НЕ трогает
malware-watch.sh / bait-watch.py / malware-watch-hb.sh и их стейт — только
ЧИТАЕТ общий флаг тишины и дописывает в общий muted.log (та же схема).

ПРАВИЛА (пороги подобраны по замеру 28.07, 7.5 ч живого журнала):
  A. authkeys — любая запись в authorized_keys / sshd_config.
     Замер: 0 РЕАЛЬНЫХ событий за 7.5 ч (65 записей в журнале были
     CONFIG_CHANGE от загрузки правил, а не действия). Значит ложных ~0,
     а ловит подсадку краденого ключа. Это главное правило файла.
  B. secrets_read с НЕИЗВЕСТНОЙ программой — программа вне белого списка
     трогает ключи/токены. Белый список засевается из уже накопленного
     журнала (24 программы), дальше новая программа даёт РОВНО ОДНО
     сообщение и сама попадает в список.
  C. всплеск — один процесс прочитал >= BURST_N разных секретных файлов
     за BURST_T секунд.
     ⚠️ ЧЕСТНО: правило СЛАБОЕ. Замер показал, что наш собственный grep
     штатно читает 97 разных секретных файлов за 60 с (автоматические сканы
     сами метут файловую систему). Порог пришлось поднять ВЫШЕ этого
     (150), иначе поток ложных. Сбор 25.07 читал скромный набор, но
     6 раз подряд — такой почерк это правило может и НЕ поймать.
     Оставлено как дешёвая страховка от грубого сплошного сбора, не более.

ШУМ. Главный механизм экономии — НЕ пороги, а подавление повторов:
ключ подавления (правило+программа/путь) с TTL, поэтому 1006 обращений
одной и той же программы к secrets.env дадут максимум 1 сообщение в сутки, а не 1006.

ТИШИНА. /var/lib/malware-watch/mute — unix-время, до которого не слать.
Файл только ЧИТАЕТСЯ, никогда не пишется. Заглушённое уходит в
/var/log/malware-watch/muted.log в том же формате, что у вотчера.
"""
import os, re, sys, json, time, html, subprocess

STATE   = "/var/lib/audit-bridge"
AUDITLOG= "/var/log/audit/audit.log"
MUTEF   = "/var/lib/malware-watch/mute"          # только чтение
MUTEDLOG= "/var/log/malware-watch/muted.log"     # общий с вотчером
OWNLOG  = "/var/log/audit-bridge.log"
ENVF    = "/etc/malware-watch.env"               # TG_TOKEN / TG_CHAT

POSF    = os.path.join(STATE, "pos.json")
BUDGETF = os.path.join(STATE, "budget.json")
ALLOWF  = os.path.join(STATE, "exe-allowlist")
DEDUPF  = os.path.join(STATE, "dedup.json")

BURST_N = 150      # см. оговорку выше: наш штатный максимум — 97
BURST_T = 60
DEDUP_TTL_NEWEXE = 86400
DEDUP_TTL_AUTHKEY= 3600
DEDUP_TTL_BURST  = 86400

# ЖЁСТКИЙ СУТОЧНЫЙ ПОТОЛОК НА ПРАВИЛО. Замер 28.07 сразу после засева дал
# 1 сообщение за 4 минуты — это ХВОСТ ОБУЧЕНИЯ (каждая новая программа
# сообщает о себе один раз и попадает в список), а не установившийся режим.
# Доказать установившийся режим за 4 минуты нельзя, поэтому худший случай
# ограничен явно: даже если обучение затянется, поток НЕ превысит потолок.
# authkeys НЕ ограничиваем — это главное правило, замер дал 0 событий за
# 7.5 ч, и глушить подсадку ключа ради тишины нельзя.
DAILY_CAP = {"newexe": 5, "burst": 3, "authkeys": 8}
# authkeys получил потолок 23.08.2026: замер обещал 0 событий в сутки,
# по факту вышло 2316. Потолок 8 — заведомо выше любого реального числа
# правок ключей за день, но лавину останавливает. Заглушённое видно в
# /var/log/audit-bridge.log строкой CAPPED.

# ПОТОЛОК ЧАСТОТЫ НА ОДИН И ТОТ ЖЕ ПОВОД — 30 минут, ЖЁСТКО.
# Введён после промаха 28.07: кто-то запустил боевой отправитель вручную, и оператору
# ушли 4 сообщения при действующем тихом режиме. Здесь ограничение стоит в
# ЕДИНСТВЕННОЙ точке отправки, поэтому его нельзя обойти, добавив новое
# правило: даже НАСТОЯЩАЯ тревога по тому же поводу уйдёт не чаще раза в 30 мин.
MIN_INTERVAL = 1800
RATEF   = os.path.join(STATE, "ratelimit.json")
PENDINGF= os.path.join(STATE, "pending.json")   # недоставленные тревоги
MAX_BYTES_PER_RUN= 64 * 1024 * 1024   # предохранитель от разгона

RX_HDR  = re.compile(r'msg=audit\((\d+)\.(\d+):(\d+)\)')
RX_EXE  = re.compile(r'\bexe="([^"]+)"')
RX_KEY  = re.compile(r'\bkey="([a-z_]+)"')
RX_PID  = re.compile(r'\bpid=(\d+)')
RX_NAME = re.compile(r'\bname="([^"]+)"')

# подстроки путей «драгоценных» файлов — попадают в текст тревоги первыми
JEWEL = tuple(x for x in os.environ.get("AUDIT_JEWEL", "").split(",") if x) or (
    ".secrets", ".env", "id_rsa", "id_ed25519", ".aws/credentials", ".netrc")

# ── ФИЛЬТР ШУМА ПРАВИЛА A (23.08.2026) ────────────────────────────────────
# Правило A следит за ВСЕМ каталогом .ssh, а туда пишут не только ключи.
# Сокеты мультиплексора ssh (ControlPath ~/.ssh/cm/...) создаются и удаляются
# на КАЖДОЕ соединение и имеют СЛУЧАЙНОЕ имя — из-за этого ключ подавления
# ни разу не совпадал, и оператору за сутки ушло больше 2300 тревог «изменён файл
# ключей входа», ни одна из которых не была настоящей. Дальше сообщаем только
# про файлы, которые ДЕЙСТВИТЕЛЬНО решают, кого пускать внутрь.
AUTHKEY_IGNORE = re.compile(r'(^|/)(cm|sockets|master|\.cache)(/|$)')
# ⚠️ 29.09.2026: убраны config, id_* и *.pub. Это ключи и настройки, с которыми
# ЭТОТ сервер ходит наружу, — они не решают, кого пускают ВНУТРЬ. Пример шума:
# «ИЗМЕНЁН ФАЙЛ КЛЮЧЕЙ ВХОДА … mini_ozon_socks.pub, программа ssh-keygen» —
# пользователь сгенерировал себе ключ для туннеля. Добавлены ~/.ssh/rc и
# ~/.ssh/environment: они ВЫПОЛНЯЮТСЯ при каждом входе по ssh — это закрепление.
# authorized_keys и sshd_config (включая sshd_config.d/*) — как и было.
AUTHKEY_INTEREST = re.compile(
    r'(^|/)(authorized_keys[^/]*|sshd_config[^/]*|rc|environment)$'
    r'|/sshd_config\.d/[^/]+$')


# ── СХЛОПЫВАНИЕ ВЕРСИОНИРОВАННЫХ ПУТЕЙ (24.08.2026) ───────────────────────
# Правило B помнит программы по ПОЛНОМУ пути exe. Claude Code живёт как
# ~/.local/share/claude/versions/<версия> и обновляется почти ежедневно, так
# что каждая новая версия выглядела «программой, которая раньше к секретам не
# обращалась», и оператору уходило сообщение. За две недели в списке накопилось
# 18 версий одного и того же Claude Code. Схлопываем версию в звёздочку: программа
# считается той же самой, а НОВАЯ (не Claude Code) по-прежнему сообщит о себе.
# ⚠️ Честная оговорка: подмену самого бинаря Claude Code это правило теперь не
# заметит — но оно и не про подлинность файла, а про «кто читает секреты».
# Подлинностью бинарей занимается malware-watch.
VERSIONED = re.compile(r'(/\.local/share/claude/versions/)[^/]+$')


# ── НАША ЕЖЕДНЕВНАЯ ЗОЛОТАЯ КОПИЯ (29.09.2026) ─────────────────────────────
# (пример) ночной бэкап-юнит копирует секреты в архив: `cp` читает
# ~156 разных секретных файлов за минуту — ровно порог правила C. Итог: каждое
# утро «📚 СПЛОШНОЙ СБОР СЕКРЕТОВ» (25, 26, 27.09 — замер по audit.log.3:
# pid cp=156 файлов/60 с, tar=75). Узко: глушим ТОЛЬКО cp/tar и ТОЛЬКО пока
# юнит копии работает или закончил не больше 15 минут назад. Любая другая
# программа (python, curl, scp…) в это же окно по-прежнему даёт тревогу.
# ⚠️ Честно: cp/tar злоумышленника, подгаданный под 04:30, это правило не увидит.
BACKUP_UNIT = os.environ.get("AUDIT_BACKUP_UNIT", "")   # имя вашего systemd-юнита бэкапа секретов; пусто = правило не нужно
BACKUP_TOOLS = {"/usr/bin/cp", "/usr/bin/tar"}


def backup_running(ts):
    if not BACKUP_UNIT:
        return False
    try:
        r = subprocess.run(["systemctl", "show", BACKUP_UNIT, "--timestamp=unix",
                            "-p", "ActiveState", "-p", "InactiveEnterTimestamp",
                            "-p", "ExecMainStartTimestamp"],
                           capture_output=True, text=True, timeout=10)
        kv = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
    except Exception:
        return False
    if kv.get("ActiveState") in ("active", "activating", "deactivating"):
        return True
    def num(v):
        v = (v or "").lstrip("@").strip()
        return int(v) if v.isdigit() else 0
    start, end = num(kv.get("ExecMainStartTimestamp")), num(kv.get("InactiveEnterTimestamp"))
    return bool(start and end and start - 60 <= ts <= end + 900 and time.time() - end < 3600)


def norm_exe(exe):
    """Путь для сверки с белым списком: версия схлопнута в '*'."""
    return VERSIONED.sub(r'\1*', exe or "")


def authkey_names(names):
    """Оставляет только осмысленные для безопасности пути.
    known_hosts намеренно НЕ включён: он меняется при каждом новом хосте
    и подсадку ключа не означает."""
    out = []
    for n in names:
        if AUTHKEY_IGNORE.search(n):
            continue
        if n.endswith("/known_hosts") or "/known_hosts." in n:
            continue
        if AUTHKEY_INTEREST.search(n):
            out.append(n)
    return out


def log(msg):
    try:
        with open(OWNLOG, "a") as f:
            f.write("%s\t%s\n" % (time.strftime("%F %T", time.gmtime()), msg))
    except Exception:
        pass


def jload(p, d):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return d


def jsave(p, o):
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(o, f)
    os.replace(tmp, p)


def muted_until():
    try:
        with open(MUTEF) as f:
            v = f.read().strip()
        return int(v) if v.isdigit() else 0
    except Exception:
        return 0


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


def _post(title, body):
    """Реальная отправка. Возвращает True ТОЛЬКО если Telegram ответил ok:true.

    ⚠️ ДЕФЕКТ, КОТОРЫЙ ЗДЕСЬ ЧИНИТСЯ (найден 28.07): раньше «SENT» писалось
    сразу после curl, БЕЗ разбора ответа. Telegram мог вернуть 400 (например,
    из-за спецсимвола в имени файла), сообщение терялось, а журнал уверял,
    что доставлено. Это худший вид молчания: тревоги нет, и следа нет.
    Теперь успех = строго ok:true, всё остальное — недоставка.
    """
    env = {}
    try:
        with open(ENVF) as f:
            for ln in f:
                if "=" in ln and not ln.strip().startswith("#"):
                    k, _, v = ln.strip().partition("=")
                    env[k] = v.strip().strip('"').strip("'")
    except Exception as e:
        log("env read failed: %s" % e)
        return False
    tok, chat = env.get("TG_TOKEN"), env.get("TG_CHAT")
    text = "%s\n%s" % (title, body)
    wh_ok = _webhook(env.get("ALERT_WEBHOOK_URL"), text)
    if not tok or not chat:
        if wh_ok is None:
            log("no TG_TOKEN/TG_CHAT and no ALERT_WEBHOOK_URL — alert not sent")
            return False
        return bool(wh_ok)
    try:
        r = subprocess.run(
            ["curl", "-s", "-m", "15", "-X", "POST",
             "https://api.telegram.org/bot%s/sendMessage" % tok,
             "-d", "chat_id=%s" % chat,
             "-d", "parse_mode=HTML",
             "-d", "disable_web_page_preview=true",
             "--data-urlencode", "text=%s" % text],
            capture_output=True, timeout=25)
    except Exception as e:
        log("DELIVERY-FAIL curl не выполнился: %s" % e)
        return bool(wh_ok)
    out = (r.stdout or b"").decode("utf-8", "replace")
    try:
        ok = json.loads(out).get("ok") is True
    except Exception:
        ok = False
    if not ok:
        # тело ответа — в журнал, чтобы причина читалась ГЛАЗАМИ, а не гадалась
        log("DELIVERY-FAIL rc=%s ответ: %s" % (r.returncode, out.replace("\n", " ")[:400]))
    return bool(ok or wh_ok)


def flush_pending():
    """Досылка недоставленного. Тишина гасит и очередь — иначе всё
    накопленное разом улетит человеку в момент снятия тишины (тот же
    приём, что в основном стороже)."""
    if muted_until() > time.time():
        return
    q = jload(PENDINGF, [])
    if not q:
        return
    left, ok = [], True
    for item in q:
        if ok and _post(item["title"], item["body"]):
            rl = jload(RATEF, {})
            rl[item["cause"]] = time.time()
            jsave(RATEF, rl)
            log("SENT(из очереди) %s" % item["title"].replace("\n", " "))
        else:
            ok = False          # первая же неудача — остальное оставляем на потом
            left.append(item)
    jsave(PENDINGF, left)
    if left:
        log("в очереди недоставленных осталось: %d" % len(left))


def send(cause, title, body):
    """Единственная точка отправки. Порядок проверок ОБЯЗАТЕЛЕН:
       1) тишина  2) потолок частоты  3) только потом отправка."""
    if muted_until() > time.time():          # ПЕРВОЙ СТРОКОЙ, без исключений
        first = title.replace("\n", " ")
        try:
            with open(MUTEDLOG, "a") as f:
                f.write("%s\tMUTED\t%s\n" % (time.strftime("%F %T", time.gmtime()), first))
        except Exception as e:
            log("muted.log write failed: %s" % e)
        log("MUTED %s" % first)
        return
    first = title.replace("\n", " ")
    # потолок частоты по поводу — 30 минут
    rl = jload(RATEF, {})
    now = time.time()
    if rl.get(cause, 0) > now - MIN_INTERVAL:
        log("RATELIMIT(%s) %s" % (cause, first))
        return
    if _post(title, body):
        rl[cause] = now                      # засчитываем ТОЛЬКО доставленное
        jsave(RATEF, rl)
        log("SENT %s" % first)
    else:
        # НЕ трогаем потолок частоты: недоставка не должна «съедать» попытку,
        # иначе потерянная тревога ещё и заблокирует повтор на 30 минут.
        q = jload(PENDINGF, [])
        q.append({"cause": cause, "title": title, "body": body, "ts": now})
        jsave(PENDINGF, q[-200:])            # очередь не растёт бесконечно
        log("ОТЛОЖЕНО в очередь недоставленных: %s" % first)


def main():
    os.makedirs(STATE, mode=0o700, exist_ok=True)
    flush_pending()          # сперва досылаем то, что не ушло в прошлый раз
    try:
        st = os.stat(AUDITLOG)
    except Exception as e:
        log("no audit log: %s" % e)
        return 0

    pos = jload(POSF, {})
    seeding = not os.path.exists(ALLOWF)

    # ── РОТАЦИЯ ЖУРНАЛА ────────────────────────────────────────────────────
    # ⚠️ ДЕФЕКТ, КОТОРЫЙ ЗДЕСЬ ЧИНИТСЯ (найден 28.07): раньше при смене inode
    # мы просто начинали читать новый файл с нуля, а ХВОСТ старого — всё, что
    # дописалось между последним чтением и ротацией — терялся молча. Окно до
    # 2 минут (шаг таймера), и ровно в него влезает подсадка ключа. После
    # перехода на 200 МБ ротация стала регулярной, так что это не теория.
    # Теперь: если inode сменился, сперва дочитываем ХВОСТ повёрнутого файла
    # (auditd переименовывает его в audit.log.1) по сохранённому смещению.
    tail_src = None
    if pos.get("ino") is not None and pos.get("ino") != st.st_ino and not seeding:
        rotated = AUDITLOG + ".1"
        try:
            rst = os.stat(rotated)
            if rst.st_ino == pos["ino"] and rst.st_size > pos.get("off", 0):
                tail_src = (rotated, pos.get("off", 0))
                log("ротация: дочитываю хвост %s с %d" % (rotated, pos.get("off", 0)))
            elif rst.st_ino != pos["ino"]:
                log("ротация: хвост потерян — inode %s не совпал с сохранённым" % rst.st_ino)
        except Exception as e:
            log("ротация: хвост недоступен (%s)" % e)

    off = pos.get("off", 0) if pos.get("ino") == st.st_ino else 0
    if off > st.st_size:
        off = 0
    if seeding:
        off = 0   # первый запуск: пройти весь журнал, засеять список, НЕ слать
        tail_src = None

    allow = set()
    if not seeding:
        try:
            with open(ALLOWF) as f:
                allow = {l.strip() for l in f if l.strip()}
        except Exception:
            pass

    dedup = {k: v for k, v in jload(DEDUPF, {}).items() if v > time.time()}

    sysev = {}          # eid -> (ts, pid, exe, key)
    paths = {}          # eid -> set(name)
    read_bytes = 0
    # источники по порядку: сперва ХВОСТ повёрнутого файла (если была
    # ротация), потом текущий журнал
    sources = ([tail_src] if tail_src else []) + [(AUDITLOG, off)]
    for src_path, src_off in sources:
      with open(src_path, errors="ignore") as f:
        f.seek(src_off)
        for ln in f:
            read_bytes += len(ln)
            if read_bytes > MAX_BYTES_PER_RUN:
                log("hit MAX_BYTES_PER_RUN, will continue next run")
                break
            if ln.startswith("type=SYSCALL"):
                k = RX_KEY.search(ln)
                if not k or k.group(1) not in ("secrets_read", "authkeys"):
                    continue
                h = RX_HDR.search(ln)
                if not h:
                    continue
                e = RX_EXE.search(ln)
                p = RX_PID.search(ln)
                sysev[h.group(3)] = (int(h.group(1)),
                                     p.group(1) if p else "?",
                                     e.group(1) if e else "?",
                                     k.group(1))
            elif ln.startswith("type=PATH"):
                h = RX_HDR.search(ln)
                if h and h.group(3) in sysev:
                    n = RX_NAME.search(ln)
                    if n:
                        paths.setdefault(h.group(3), set()).add(n.group(1))
        # смещение запоминаем ТОЛЬКО по текущему журналу: если бы мы
        # записали позицию внутри повёрнутого файла, следующий прогон
        # начал бы читать новый журнал не с того места
        if src_path == AUDITLOG:
            newoff = f.tell()

    alerts = []
    seen_exes = set()
    burst = {}          # (pid,exe) -> [(ts,name)]

    for eid, (ts, pid, exe, key) in sysev.items():
        seen_exes.add(norm_exe(exe))
        names = paths.get(eid, set())

        # --- A. запись в authorized_keys / sshd_config ---
        if key == "authkeys":
            # ОДНО сообщение на СОБЫТИЕ, а не на каждый путь в нём: одна правка
            # файла даёт несколько записей PATH (сам файл + родительский
            # каталог), и по пути на сообщение это давало бы 2-3 штуки на одно
            # действие. Ключ подавления — по набору путей.
            nm = sorted(authkey_names(names))
            if not nm:
                continue          # шум: сокет мультиплексора, временный файл и т.п.
            dk = "authkeys:%s" % "|".join(nm)
            if dedup.get(dk, 0) > time.time():
                continue
            dedup[dk] = time.time() + DEDUP_TTL_AUTHKEY
            alerts.append(("authkeys",
                "🔑 <b>ИЗМЕНЁН ФАЙЛ КЛЮЧЕЙ ВХОДА</b>",
                "<blockquote>• файл: <code>%s</code>\n• программа: <code>%s</code>\n"
                "• время: %s UTC\n• это может быть подсадка чужого ключа для входа "
                "без пароля</blockquote>"
                % (html.escape(", ".join(nm[:4])), html.escape(exe),
                   time.strftime("%F %T", time.gmtime(ts)))))
            continue

        # --- B/C. чтение секретов ---
        if seeding:
            continue
        nexe = norm_exe(exe)
        if nexe not in allow:
            dk = "newexe:%s" % nexe
            if dedup.get(dk, 0) <= time.time():
                dedup[dk] = time.time() + DEDUP_TTL_NEWEXE
                jew = [n for n in names if any(j in n for j in JEWEL)]
                alerts.append(("newexe",
                    "🕵 <b>НОВАЯ ПРОГРАММА ЧИТАЕТ СЕКРЕТЫ</b>",
                    "<blockquote>• программа: <code>%s</code>\n• файлы: <code>%s</code>\n"
                    "• время: %s UTC\n• раньше эта программа к ключам/токенам не "
                    "обращалась</blockquote>"
                    % (html.escape(exe),
                       html.escape(", ".join(sorted(jew or names)[:5]) or "?"),
                       time.strftime("%F %T", time.gmtime(ts)))))
            allow.add(nexe)  # сообщаем один раз, дальше это известная программа
        for n in names:
            burst.setdefault((pid, exe), []).append((ts, n))

    # --- C. всплеск ---
    if not seeding:
        for (pid, exe), lst in burst.items():
            lst.sort()
            for i, (ts0, _) in enumerate(lst):
                s = set()
                for ts2, n2 in lst[i:]:
                    if ts2 - ts0 > BURST_T:
                        break
                    s.add(n2)
                if len(s) >= BURST_N:
                    if exe in BACKUP_TOOLS and backup_running(ts0):
                        log("BURST-BACKUP (не шлю: идёт золотая копия) %s %d файлов" % (exe, len(s)))
                        break
                    dk = "burst:%s" % exe
                    if dedup.get(dk, 0) <= time.time():
                        dedup[dk] = time.time() + DEDUP_TTL_BURST
                        alerts.append(("burst",
                            "📚 <b>СПЛОШНОЙ СБОР СЕКРЕТОВ</b>",
                            "<blockquote>• программа: <code>%s</code>\n"
                            "• прочитано разных секретных файлов: <b>%d</b> за %d с\n"
                            "• время: %s UTC\n• похоже на почерк сбора 25.07</blockquote>"
                            % (html.escape(exe), len(s), BURST_T,
                               time.strftime("%F %T", time.gmtime(ts0)))))
                    break

    if seeding:
        allow = seen_exes
        with open(ALLOWF, "w") as f:
            f.write("\n".join(sorted(allow)) + "\n")
        os.chmod(ALLOWF, 0o600)
        log("SEEDED allowlist with %d exes, no alerts sent (learning pass)" % len(allow))
    else:
        with open(ALLOWF, "w") as f:
            f.write("\n".join(sorted(allow)) + "\n")

    today = time.strftime("%F", time.gmtime())
    budget = jload(BUDGETF, {})
    if budget.get("day") != today:
        budget = {"day": today}
    sent = held = 0
    for rule, title, body in alerts:
        cap = DAILY_CAP.get(rule)
        if cap is not None:
            used = budget.get(rule, 0)
            if used >= cap:
                held += 1
                log("CAPPED(%s) %s" % (rule, title.replace("\n", " ")))
                continue
            budget[rule] = used + 1
        send("%s:%s" % (rule, title[:40]), title, body)
        sent += 1
        if sent >= 10:                      # предохранитель от лавины в один прогон
            held += len(alerts) - sent
            break
    if held:
        log("held %d alerts (daily cap / per-run cap)" % held)
    jsave(BUDGETF, budget)

    jsave(POSF, {"ino": st.st_ino, "off": newoff})
    jsave(DEDUPF, dedup)
    if alerts:
        log("run: %d alerts, %d events parsed" % (len(alerts), len(sysev)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
