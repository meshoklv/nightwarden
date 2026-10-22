#!/usr/bin/env python3
"""Утренняя сводка охраны: ОДНО спокойное сообщение в сутки вместо потока тревог.

Читает журналы malware-watch и bait-watch, группирует по-человечески и шлёт оператору
одно сообщение с кнопками. Пустая сводка — это хорошо: она подтверждает, что охрана жива.

Запуск:  mw-digest.py [--dry-run] [--hours N] [--stdout]
  --dry-run  — ничего не отправлять, напечатать текст (для тестов)
  --hours N  — окно вместо «с прошлой сводки»
"""
import argparse
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone

ENV_FILE = os.environ.get("MWD_ENV", "/etc/malware-watch.env")
CONF_FILE = os.environ.get("MWD_CONF", "/etc/mw-digest.conf")
# пути можно переопределить окружением — нужно для тестов на подставных журналах
MW_EVENTS = os.environ.get("MWD_MW_EVENTS", "/var/log/malware-watch/events.jsonl")
MUTED_LOG = os.environ.get("MWD_MUTED_LOG", "/var/log/malware-watch/muted.log")
BAIT_EVENTS = os.environ.get("MWD_BAIT_EVENTS", "/var/log/bait-watch/events.jsonl")
STATE_DIR = os.environ.get("MWD_STATE_DIR", "/var/lib/malware-watch")
MUTE_FILE = os.path.join(STATE_DIR, "mute")
HB_FILE = os.path.join(STATE_DIR, "heartbeat")
LAST_RUN = os.path.join(STATE_DIR, "digest-last-run")
LAST_TEXT = os.path.join(STATE_DIR, "digest-last-text.html")
DIGEST_LOG = "/var/log/malware-watch/digest.log"
BUTTONS = "/usr/local/sbin/mw-buttons.py"
BTN_ENV_FILE = os.environ.get("MWD_BTN_ENV", "/etc/mw-buttons.env")
MW_SCRIPT = os.environ.get("MWD_MW_SCRIPT", "/usr/local/sbin/malware-watch.sh")
PLACEHOLDERS = {"", "СЮДА_ТОКЕН", "PUT_TOKEN_HERE", "<токен>"}

TG_LIMIT = 4096


# ─────────────────────────── конфиг ───────────────────────────
def load_env(path):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                # срезаем комментарий в конце строки (' #'), но не '#' внутри значения
                v = re.split(r"\s+#", v, maxsplit=1)[0]
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


ENV = load_env(ENV_FILE)
CONF = load_env(CONF_FILE)
BTN_ENV = load_env(BTN_ENV_FILE)


def conf_int(key, default):
    try:
        return int(CONF.get(key, default))
    except (TypeError, ValueError):
        return default


WINDOW_H = conf_int("DIGEST_WINDOW_HOURS", 24)
HB_STALE_H = conf_int("DIGEST_HB_STALE_HOURS", 1)
IGNORE_MUTE = conf_int("DIGEST_IGNORE_MUTE", 0)   # 0 = сводка молчит в тихом режиме
SCHEDULE_UTC = CONF.get("DIGEST_SCHEDULE_UTC", "07:00")
SEND_WINDOW_MIN = conf_int("DIGEST_SEND_WINDOW_MIN", 90)
TZ_OFFSET = conf_int("DIGEST_TZ_OFFSET", 0)          # часы от UTC для местного времени в тексте сводки
LOCAL_TZ = timezone(timedelta(hours=TZ_OFFSET))


def local(ts):
    return datetime.fromtimestamp(ts, LOCAL_TZ)


def hm(ts):
    return local(ts).strftime("%H:%M")


def dm(ts):
    return local(ts).strftime("%d.%m %H:%M")


def human_dur(sec):
    sec = int(max(sec, 0))
    if sec < 90:
        return f"{sec} сек"
    if sec < 5400:
        return f"{sec // 60} мин"
    if sec < 36 * 3600:
        return f"{sec // 3600} ч"
    return f"{sec // 86400} дн"


def plural(n, one, few, many):
    """21 случай / 23 случая / 25 случаев — иначе счётчики читаются как машинные."""
    n = int(n)
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} {one}"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return f"{n} {few}"
    return f"{n} {many}"


def times(n):
    """1 раз, 2 раза, 5 раз — чтобы читалось по-человечески."""
    n = int(n)
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} раз"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return f"{n} раза"
    return f"{n} раз"


def esc(s):
    return html.escape(str(s), quote=False)


# ─────────────────────────── чтение журналов ───────────────────────────
def read_jsonl(path, since_ts, ts_of):
    """Потоково читает jsonl и отдаёт записи новее since_ts. Битые строки пропускает."""
    rows = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                t = ts_of(d)
                if t is None or t < since_ts:
                    continue
                d["_ts"] = t
                rows.append(d)
    except OSError:
        pass
    return rows


def mw_ts(d):
    s = d.get("ts")
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def bait_ts(d):
    t = d.get("ts")
    if isinstance(t, (int, float)):
        return float(t)
    return None


# ─────────────────── перевод на человеческий язык ───────────────────
# (kind-регэксп, короткое имя события, подсказка «что это значит»)
KIND_RULES = [
    # ⚠️ Только НАСТОЯЩЕЕ убийство. Раньше сюда по словам «бэкдор|mirai» попадал
    # «слушатель на порту ботнета» — событие другого рода, и сводка писала про него
    # «уже остановлена». Это враньё в успокаивающую сторону.
    (r"убит|обезврежен|остановлен[аи]?\b",
     "сторож нашёл и остановил чужую программу",
     "kill"),
    (r"ботнет|mirai|telnet-loader",
     "открылся порт, на котором обычно сидят ботнеты",
     "botnet_port"),
    (r"\bC2\b|управляющ|стук",
     "с сервера пытались связаться с сетью, из которой нас ломали 25 июля",
     "c2"),
    (r"автозапуск|закреплен",
     "менялись программы, которые запускаются при включении сервера",
     "autostart"),
    (r"VPN|killswitch|туннел",
     "показалось, что интернет пошёл мимо защищённого канала",
     "vpn"),
    (r"loopback",
     "программа начала слушать порт только внутри сервера (наружу не торчит)",
     "port_local"),
    (r"слушател|listener|порт",
     "на сервере появился новый открытый порт",
     "port"),
    (r"удалённым бинар|удаленным бинар",
     "программа работала без своего файла на диске",
     "deleted_exe"),
    (r"модул|ядр",
     "в системе появилась новая низкоуровневая надстройка",
     "kmod"),
]

# ⛔ КЛАССИФИКАЦИИ ПО ИМЕНИ ПРОГРАММЫ ЗДЕСЬ БОЛЬШЕ НЕТ И БЫТЬ НЕ ДОЛЖНО.
# Раньше сводка сама решала «свой/чужой» по командной строке (python3|grep|node|…)
# и на этом отбелила настоящий стилер, запущенный как `python3 /tmp/idx-sync.py`:
# ловушка присвоила ему CRIT «читает ТОЛЬКО файлы-секреты», а сводка написала
# «чужого нет». Имя программы подделывается — доказано тестом с `updatedb`.
# Вердикт «свой/чужой» принимает ЛОВУШКА по ПОВЕДЕНИЮ, сводка его только пересказывает.
# Единственное, что мы учитываем помимо severity, — собственные флаги ловушки:
# allowlisted (заранее разрешено) и maint (объявленное окно обслуживания).


# ⚠️ 29.09.2026: служебные строки журнала — НЕ события. Раньше они шли в «Что
# шумело»: 261 почасовая строка «то же отличие держится (N прогонов)» давала
# «263 случая, чего я не умею объяснить», а ежечасное «VPN в порядке» (vpnks-ok)
# попадало под слово VPN и превращалось в «интернет пошёл мимо защищённого
# канала … похоже на ложную тревогу» — тревоги не было ни одной.
SERVICE_KINDS = re.compile(
    r"^(alert-repeat|persist-drift-repeat|persist-drift-back|persist-back-to-known|"
    r"persist-pending|vpnks-ok|vpnks-closed|digest-sent|accept|suid-timeout-opt|"
    r"процесс ждёт перезапуска после обновления)$")


def classify_kind(kind):
    if SERVICE_KINDS.search(kind or ""):
        return None, "skip"
    for rx, phrase, tag in KIND_RULES:
        if re.search(rx, kind or "", re.I):
            return phrase, tag
    # незнакомое название сторожа человеку сырым не показываем — это кодерский жаргон.
    # Само название останется в «Подробностях».
    if not re.search(r"[а-яё]", kind or "", re.I):
        return "сторож отметил что-то, чего я пока не умею объяснить словами", "other"
    return (kind or "неизвестное событие"), "other"


def case_key(detail_plain, fp=""):
    """Ключ РАЗНОГО случая. Одно и то же событие сторож напоминает много раз;
    человек должен видеть «2 случая», а не «11 вредоносов»."""
    if fp:                      # у сторожа есть устойчивый отпечаток — он и есть «случай»
        return "fp:" + fp
    pid = re.search(r"PID\s+(\d+)", detail_plain)
    exe = re.search(r"exe=(\S+)", detail_plain)
    if pid or exe:
        return f"proc:{pid.group(1) if pid else '?'}|{exe.group(1) if exe else '?'}"
    ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", detail_plain)
    if ip:
        return "ip:" + ip.group(1)
    port = re.search(r"порт[ыа]?[:\s]+(\d+)", detail_plain, re.I)
    if port:
        return "port:" + port.group(1)
    return "text:" + detail_plain.split("\n")[0][:120]


def collect_mw(rows):
    """Группирует события сторожа: tag -> {count, first, last, sev, kinds, details}"""
    groups = {}
    for d in rows:
        kind = d.get("kind", "")
        sev = (d.get("sev") or "").upper()
        phrase, tag = classify_kind(kind)
        if tag == "skip":
            continue
        g = groups.setdefault(tag, {
            "phrase": phrase, "count": 0, "first": d["_ts"], "last": d["_ts"],
            "sev": Counter(), "details": Counter(), "kinds": Counter(), "full": [],
            "cases": set(), "own_cases": set(),
        })
        g["count"] += 1
        g["first"] = min(g["first"], d["_ts"])
        g["last"] = max(g["last"], d["_ts"])
        g["sev"][sev] += 1
        g["kinds"][kind] += 1
        det = re.sub(r"<[^>]+>", "", d.get("detail", "") or "").strip()
        first_line = det.split("\n")[0][:200]
        if first_line:
            g["details"][first_line] += 1
        if len(g["full"]) < 20:
            g["full"].append(det[:1200])
        key = case_key(det, d.get("fp") or "")
        g["cases"].add(key)
        if re.search(r"детектор|malware-watch|bait-watch|audit-bridge", det, re.I):
            g["own_cases"].add(key)
    return groups


NO_REASON = "опасное по мнению ловушки, но причина в записи не сохранена"


def collect_bait(rows):
    """Приманки. Вердикт берём У ЛОВУШКИ, а не пересчитываем по именам программ.

    «Требует внимания» = ловушка поставила WARN/CRIT И не пометила это как заранее
    разрешённое (allowlisted) или объявленное окно обслуживания (maint).
    Имя программы идёт только как УЛИКА в тексте, на вердикт оно не влияет.
    """
    attention = []
    reasons = Counter()
    sev_count = Counter()
    baits = Counter()
    declared = 0
    first = last = None
    total = 0
    service_events = Counter()
    for d in rows:
        ev = d.get("event")
        if ev != "bait_read":
            service_events[ev] += 1
            continue
        total += 1
        first = d["_ts"] if first is None else min(first, d["_ts"])
        last = d["_ts"] if last is None else max(last, d["_ts"])
        proc = d.get("proc") or {}
        cmd = (proc.get("cmdline") or proc.get("comm") or "?").strip()
        baits[d.get("bait", "?")] += 1
        sev = (d.get("severity") or "").upper()
        sev_count[sev] += 1
        if sev not in ("WARN", "CRIT"):
            continue
        if d.get("allowlisted") or d.get("maint"):
            declared += 1
            continue
        reason = d.get("reason") or NO_REASON
        attention.append({
            "ts": d["_ts"], "cmd": cmd[:160], "sev": sev, "reason": reason,
            "where": proc.get("where") or proc.get("container") or "",
            "bait": d.get("bait", "?"),
        })
        reasons[(sev, reason)] += 1
    return {
        "total": total, "attention": attention, "reasons": reasons, "baits": baits,
        "sev": sev_count, "declared": declared,
        "first": first, "last": last, "service": service_events,
    }


def collect_muted(since_ts):
    """Заглушённые тревоги. Пока стоит тихий режим — это единственное место,
    где человек их вообще увидит, поэтому в сводку они обязаны попадать."""
    items = Counter()
    red = 0
    total = 0
    try:
        f = open(MUTED_LOG, errors="replace")
    except OSError:
        return {"total": 0, "red": 0, "items": items}
    with f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            try:
                t = datetime.strptime(parts[0].strip(), "%Y-%m-%d %H:%M:%S") \
                    .replace(tzinfo=timezone.utc).timestamp()
            except ValueError:
                continue
            if t < since_ts:
                continue
            total += 1
            raw = parts[2]
            is_red = "🔴" in raw or "🚨" in raw
            # заголовок тревоги — это её первый <b>…</b>; так надёжнее, чем резать текст
            m = re.search(r"<b>(.*?)</b>", raw)
            head = re.sub(r"<[^>]+>", "", m.group(1) if m else raw).strip()
            if is_red:
                red += 1
            head = re.sub(r"^[^\wА-Яа-я\[]+", "", head)         # убрать ведущие значки
            head = re.sub(r"^\[[^\]]+\]\s*", "", head)          # убрать [malware-watch]
            head = re.split(r"(?<=[а-яё])\s{2,}|\. ", head)[0]   # только первая фраза
            items[(is_red, head[:90])] += 1
    return {"total": total, "red": red, "items": items}


# ─────────────────────────── живость охраны ───────────────────────────
def unit_active(unit):
    try:
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def liveness(now):
    hb = None
    try:
        hb = int(open(HB_FILE).read().strip())
    except (OSError, ValueError):
        hb = None
    age = None if hb is None else now - hb
    units = {u: unit_active(u) for u in
             ("malware-watch.timer", "malware-watch-hb.timer", "bait-watch.service")}
    dead_units = [u for u, s in units.items() if s not in ("active", "activating")]
    stale = hb is None or age > HB_STALE_H * 3600
    return {"hb": hb, "age": age, "units": units, "dead": dead_units, "stale": stale}


def mute_state(now):
    try:
        until = int(open(MUTE_FILE).read().strip())
    except (OSError, ValueError):
        return None
    return until if until > now else None


def muted_count(since_ts):
    n = 0
    try:
        with open(MUTED_LOG, errors="replace") as f:
            for line in f:
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                try:
                    t = datetime.strptime(parts[0].strip(), "%Y-%m-%d %H:%M:%S") \
                        .replace(tzinfo=timezone.utc).timestamp()
                except ValueError:
                    continue
                if t >= since_ts:
                    n += 1
    except OSError:
        return 0
    return n


# ─────────────────────────── сборка текста ───────────────────────────
def build(now, since_ts):
    mw_rows = read_jsonl(MW_EVENTS, since_ts, mw_ts)
    bait_rows = read_jsonl(BAIT_EVENTS, since_ts, bait_ts)
    groups = collect_mw(mw_rows)
    bait = collect_bait(bait_rows)
    live = liveness(now)
    muted = collect_muted(since_ts)
    mute_until = mute_state(now)
    span = now - since_ts
    window_txt = f"{max(1, round(span / 60))} мин" if span < 3600 else f"{round(span / 3600)} ч"

    # ── что считаем реально тревожным ──
    # 1) приманки, которые сам вотчер посчитал подозрительными и это не наши программы;
    # 2) редкие события сторожа не про автозапуск и не про VPN (порт, программа без файла);
    # 3) неотвеченная охрана.
    HEADLINE = ("kill", "c2", "botnet_port")
    bait_attention = bait["attention"]
    bait_crit = [a for a in bait_attention if a["sev"] == "CRIT"]
    kills = groups.get("kill")
    headline = [(t, groups[t]) for t in HEADLINE if t in groups]
    odd = [(tag, g) for tag, g in groups.items()
           if tag not in ("autostart", "vpn") + HEADLINE
           and (g["sev"].get("CRIT") or g["sev"].get("WARN"))]
    autostart = groups.get("autostart")

    # Сколько было CRIT за период — по ОБОИМ сторожам. Это жёсткий предохранитель:
    # при любом CRIT «спокойно» и «чужого нет» запрещены (см. ниже).
    mw_crit = sum(g["sev"].get("CRIT", 0) for g in groups.values())
    crit_total = mw_crit + len(bait_crit)

    alarm = bool(bait_attention) or bool(odd) or live["stale"] or bool(live["dead"])
    # ⛔ «спокойно» — ТОЛЬКО когда за период ноль CRIT и ноль убийств.
    calm_allowed = crit_total == 0 and not kills
    needs_ok = bool(autostart) and not alarm and not headline and calm_allowed

    P = []
    head_date = local(now).strftime("%d.%m")
    P.append(f"🛡 <b>Охрана сервера — сводка за ночь</b>")
    P.append(f"<i>{head_date}, за последние {window_txt}</i>")
    P.append("")

    # ── вердикт первой строкой ──
    if live["stale"]:
        ago = "ни разу не отчитывался" if live["age"] is None else f"молчит {human_dur(live['age'])}"
        P.append("🆘 <b>Охрана не отвечает</b>")
        P.append(f"<blockquote>Сторож {ago}. Пока он молчит, тишина ничего не значит — "
                 f"сервер надо посмотреть руками.</blockquote>")
    elif live["dead"]:
        P.append("🆘 <b>Часть охраны выключена</b>")
        P.append("<blockquote>Не работает: <b>" +
                 esc(", ".join(live["dead"])) + "</b> — включить и проверить.</blockquote>")
    elif headline:
        P.append("🚨 <b>Сработала настоящая тревога</b>")
        hl = []
        for tag, g in headline:
            msgs = g["count"]
            cases = len(g["cases"]) or 1
            когда = hm(g["first"]) if msgs == 1 else f"{hm(g['first'])}–{hm(g['last'])}"
            # ГЛАВНАЯ цифра — сколько РАЗНЫХ случаев; сколько раз про них написали — второй
            line = (f"• <b>{esc(g['phrase'])}</b> — "
                    f"<b>{plural(cases, 'случай', 'случая', 'случаев')}</b>, {когда}")
            if msgs > cases:
                line += f" (напоминаний об этом: {msgs})"
            line += "."
            if tag == "kill":
                где = ", ".join(sorted({
                    m.group(1) for det in g["full"]
                    for m in [re.search(r"exe=(\S+)", det)] if m
                }))[:120]
                if где:
                    line += f" Лежала тут: <code>{esc(где)}</code>."
                line += " Уже остановлена, следы сохранены."
            elif tag == "c2":
                ips = ", ".join(sorted({
                    m.group(1) for det in g["full"]
                    for m in [re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", det)] if m
                }))[:80]
                if ips:
                    line += f" Адрес: <code>{esc(ips)}</code>, соединение заблокировано."
            elif tag == "botnet_port":
                line += " Проверить, кто его открыл."
            hl.append(line)
        hl.append("Нажми <b>«Подробности»</b> — покажу всё, что известно.")
        P.append("<blockquote>" + "\n".join(hl) + "</blockquote>")
    elif alarm:
        P.append("⚠️ <b>Есть что посмотреть</b>")
        why = []
        if bait_attention:
            n_crit = sum(1 for a in bait_attention if a["sev"] == "CRIT")
            why.append(f"ловушка сочла подозрительными <b>{len(bait_attention)}</b> обращений "
                       f"к подставным файлам с «паролями»"
                       + (f", из них <b>{n_crit}</b> высшей важности" if n_crit else ""))
        for tag, g in odd:
            why.append(f"{esc(g['phrase'])} ({g['count']})")
        P.append("<blockquote>" + "; ".join(why) + ". Подробности — кнопкой ниже.</blockquote>")
    elif needs_ok:
        P.append("✅ <b>Ночь прошла спокойно</b>")
        P.append("<blockquote>Опасного не нашли. Накопились повторы про изменения на сервере — "
                 "какие из них ещё не закрыты — ниже.</blockquote>")
    elif calm_allowed:
        P.append("✅ <b>Ночь прошла спокойно</b>")
    else:
        # сюда попадаем, если CRIT был, но выше ни одна ветка его не показала
        P.append("⚠️ <b>Есть что посмотреть</b>")
        P.append(f"<blockquote>За период было <b>{crit_total}</b> срабатываний "
                 f"высшей важности. Ниже — что именно.</blockquote>")

    # ── совсем пусто ──
    quiet_all = (not mw_rows) and bait["total"] == 0 and calm_allowed
    if quiet_all and not live["stale"] and not live["dead"]:
        P.append("<blockquote>Ничего не происходило. Сторож на месте, "
                 f"последняя проверка {human_dur(live['age'] or 0)} назад.</blockquote>")
    else:
        # ── что шумело ──
        noise = []
        order = sorted(groups.items(), key=lambda kv: -kv[1]["count"])
        for tag, g in order:
            if tag in HEADLINE:
                continue          # это в шапке, а не в «шумело»
            cnt = g["count"]
            cases = len(g["cases"]) or 1
            if cases < cnt:
                line = (f"• <b>{plural(cases, 'случай', 'случая', 'случаев')}</b>"
                        f" — {esc(g['phrase'])} <i>(напоминаний: {cnt})</i>")
            else:
                line = f"• <b>{times(cnt)}</b> — {esc(g['phrase'])}"
            if tag == "autostart":
                own = len(g["own_cases"])
                if own:
                    line += f". Из них <b>{own}</b> — про файлы самой охраны"
                # кнопки «Это норма» нет (бот кнопок не заведён) — не обещаем её
                line += ". Что из этого ещё не закрыто — в разделе «Висит неразобранным»"
            elif tag == "vpn":
                ok = sum(1 for d in mw_rows if (d.get("kind") or "").startswith("vpnks-ok"))
                if ok:
                    line += (f". Перепроверка канала прошла успешно <b>{ok}</b> раз — "
                             f"похоже на <b>ложную тревогу</b>")
            elif tag == "port":
                nums = set(re.findall(r"\b(\d{2,5})\b", " ".join(g["details"])))
                if nums:
                    line += f" ({esc(', '.join(sorted(nums)[:4]))})"
            line += (f", {hm(g['first'])}" if hm(g["first"]) == hm(g["last"])
                     else f", {hm(g['first'])}–{hm(g['last'])}")
            noise.append(line)
        if noise:
            P.append("")
            P.append("🔁 <b>Что шумело</b>")
            P.append("<blockquote>" + "\n".join(noise) + "</blockquote>")

        # ── ловушки ──
        if bait["total"]:
            bl = [f"• Подставные файлы с «паролями» открывали <b>{times(bait['total'])}</b>"
                  f", {hm(bait['first'])}–{hm(bait['last'])}."]
            if bait_attention:
                progs = len({a["cmd"] for a in bait_attention})
                bl.append(f"• ⚠️ Ловушка насчитала "
                          f"<b>{plural(progs, 'программу', 'программы', 'программ')}</b>"
                          f", которые вели себя подозрительно "
                          f"({plural(len(bait_attention), 'обращение', 'обращения', 'обращений')})."
                          f" Признаки:")
                # сначала объяснённые признаки (красные вперёд), безымянные — в конец
                ranked = sorted(bait["reasons"].items(),
                                key=lambda kv: (kv[0][1] == NO_REASON,
                                                kv[0][0] != "CRIT", -kv[1]))
                for (sev, reason), n in ranked[:4]:
                    mark = "🔴" if sev == "CRIT" else "🟠"
                    # показываем РАЗНЫЕ команды, а не первую попавшуюся: иначе улика
                    # меняется от прогона к прогону и самое опасное может не попасть
                    seen = []
                    for a in bait_attention:
                        if a["reason"] == reason and a["cmd"] not in seen:
                            seen.append(a["cmd"])
                        if len(seen) == 2:
                            break
                    ex = "; ".join(f"<code>{esc(c[:80])}</code>" for c in seen)
                    bl.append(f"  {mark} <b>{esc(reason)}</b> — {times(n)}"
                              + (f"; кто: {ex}" if ex else ""))
                shown = sum(n for _, n in ranked[:4])
                rest = len(bait_attention) - shown
                if rest > 0:
                    bl.append(f"  • и ещё <b>{times(rest)}</b> по другим признакам — "
                              f"все они в журнале ловушки.")
                bl.append("• Названию программы не верь: имя подделывается, "
                          "ловушка судит по <b>поведению</b>.")
            else:
                # ⛔ фраза «чужого нет» разрешена ТОЛЬКО когда CRIT не было вообще
                bl.append("• Ловушка ничего подозрительного среди них не увидела."
                          if calm_allowed else
                          "• Ловушка среди них подозрительного не увидела, "
                          "<b>но за период были другие срабатывания высшей важности</b> — см. выше.")
            if bait["declared"]:
                bl.append(f"• Ещё {times(bait['declared'])} — заранее разрешённые "
                          f"и плановые работы.")
            P.append("")
            P.append("🪤 <b>Ловушки</b>")
            P.append("<blockquote>" + "\n".join(bl) + "</blockquote>")

        # ── заглушённое тихим режимом ──
        if muted["total"]:
            ml = [f"• Пока стоит тишина, я придержал "
                  f"<b>{plural(muted['total'], 'тревогу', 'тревоги', 'тревог')}</b>"
                  + (f", из них <b>{muted['red']}</b> — <b>красные</b>." if muted["red"] else ".")]
            for (is_red, head), n in sorted(muted["items"].items(),
                                            key=lambda kv: (not kv[0][0], -kv[1]))[:4]:
                ml.append(f"  {'🔴' if is_red else '•'} {esc(head)}"
                          + (f" — {times(n)}" if n > 1 else ""))
            ml.append("• Цифра — сколько РАЗ про это написали, а не сколько разных случаев: "
                      "сторож напоминает об одном и том же.")
            ml.append("• Это то, что НЕ прилетело в чат. Здесь оно показано целиком.")
            P.append("")
            P.append("🔕 <b>Что я придержал</b>")
            P.append("<blockquote>" + "\n".join(ml) + "</blockquote>")

    # ── висит неразобранным ──
    # Раньше каждое такое изменение слало отдельное красное письмо КАЖДЫЙ день.
    # Теперь напоминание — здесь, одной строкой на изменение, с командой приёма.
    try:
        pend = pending()
    except Exception:
        pend = []
    if pend:
        pl = []
        for it in pend[:8]:
            codes = ",".join(it.get("codes") or []) if isinstance(it.get("codes"), list) else str(it.get("aid") or "")
            mark = "🔴" if it.get("cls") == "red" else "•"
            pl.append(f"{mark} {esc(it.get('title') or 'изменение')}"
                      + (f" — <code>{esc(codes)}</code>" if codes else ""))
        if len(pend) > 8:
            pl.append(f"• и ещё {len(pend) - 8}")
        pl.append("<i>Твоё — прими на сервере: <code>sudo MW_ALLOW_RED=1 malware-watch.sh accept КОД</code>. "
                  "Не твоё — скажи, разберу.</i>")
        P.append("")
        P.append(f"📌 <b>Висит неразобранным: {len(pend)}</b>")
        P.append("<blockquote>" + "\n".join(pl) + "</blockquote>")

    # ── тихий режим ──
    if mute_until:
        P.append("")
        P.append("🔇 <b>Тихий режим</b>")
        P.append(f"<blockquote>• Тревоги не приходят до <b>{dm(mute_until)}</b> "
                 f"(осталось {human_dur(mute_until - now)}). Охрана всё это время работает "
                 f"и всё записывает.</blockquote>")

    # ── охрана жива ──
    if not live["stale"] and not live["dead"]:
        P.append("")
        P.append("❤️ <b>Охрана на посту</b>")
        P.append(f"<blockquote>• Сторож отчитался {human_dur(live['age'])} назад, "
                 f"ловушки и проверки работают.</blockquote>")

    text = "\n".join(P).strip()
    if len(text) > TG_LIMIT:
        text = text[:TG_LIMIT - 40].rsplit("\n", 1)[0] + "\n<i>…сводка обрезана</i>"
    last_id = None
    for d in reversed(mw_rows):
        if d.get("id"):
            last_id = d["id"]
            break
    return text, {"mw": len(mw_rows), "bait": bait["total"], "alarm": alarm,
                  "crit": crit_total, "muted": muted["total"], "muted_red": muted["red"],
                  "stale": live["stale"], "dead": live["dead"], "last_id": last_id}


# ─────────────────────────── отправка ───────────────────────────
def pending():
    """Незакрытые изменения от сторожа: [{aid,title,...}]. Пусто, если команды ещё нет."""
    # без sudo: сводка работает systemd-сервисом под root, sudoers не заводим
    if os.geteuid() != 0:
        return []
    try:
        r = subprocess.run([MW_SCRIPT, "pending-json"],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return []
    if r.returncode != 0 or not r.stdout.strip():
        return []
    # сторож отдаёт ПО ОБЪЕКТУ НА СТРОКУ (jsonl), но переживём и обычный массив
    items = []
    try:
        d = json.loads(r.stdout)
        items = d if isinstance(d, list) else (d.get("pending") or d.get("items") or [d])
    except ValueError:
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except ValueError:
                continue
    # красные — первыми, дальше по числу повторов
    ORDER = {"red": 0, "amber": 1, "white": 2}

    # Несколько изменений с ОДНИМ названием (units / units.wants / units.enabled)
    # для человека выглядят как три одинаковые кнопки. Склеиваем их в одну:
    # сторож умеет принимать коды списком через запятую.
    merged = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        title = str(it.get("title") or "изменение")
        cls = str(it.get("cls") or it.get("class") or "white").lower()
        g = merged.setdefault(title, {"title": title, "cls": cls, "codes": [],
                                      "count": 0, "id": it.get("id") or ""})
        if ORDER.get(cls, 3) < ORDER.get(g["cls"], 3):
            g["cls"] = cls                       # берём худший класс группы
        if it.get("aid"):
            g["codes"].append(str(it["aid"]))
        g["count"] += int(it.get("count") or 0)

    out = []
    for g in merged.values():
        n = len(g["codes"])
        out.append({"aid": ",".join(g["codes"]), "cls": g["cls"], "id": g["id"],
                    "count": g["count"],
                    "title": g["title"] + (f" ({n})" if n > 1 else "")})
    return sorted(out, key=lambda it: (ORDER.get(it["cls"], 3), -it["count"]))


def keyboard(items, last_id=None):
    """Клавиатура от mw-buttons.py: по кнопке «принять» на каждое незакрытое изменение."""
    cmd = [BUTTONS, "keyboard"]
    for it in items[:3]:
        aid = str(it.get("aid") or "")
        if not aid:
            continue
        cmd += ["--aid", aid, "--title", str(it.get("title") or "изменение"),
                "--cls", str(it.get("cls") or it.get("class") or "white"),
                "--id", str(it.get("id") or "")]
    if last_id:
        cmd += ["--last-id", str(last_id)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def sender():
    """Кем слать. Кнопки обрабатывает ТОТ бот, который отправил сообщение,
    поэтому при наличии отдельного бота охраны сводку шлёт он же."""
    btn = BTN_ENV.get("BTN_TG_TOKEN", "")
    if btn in PLACEHOLDERS:
        btn = ""
    if btn:
        return btn, (BTN_ENV.get("BTN_TG_CHAT") or ENV.get("TG_CHAT", "")), True
    return ENV.get("TG_TOKEN", ""), ENV.get("TG_CHAT", ""), False


def _send_webhook(text):
    """Optional JSON webhook (Slack/Discord/ntfy-style). None = not configured."""
    url = (ENV.get("ALERT_WEBHOOK_URL") or os.environ.get("ALERT_WEBHOOK_URL") or "").strip()
    if not url:
        return None
    import re as _re
    plain = html.unescape(_re.sub(r"<[^>]*>", "", text))[:3800]
    req = urllib.request.Request(
        url, data=json.dumps({"text": plain, "content": plain}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15).read()
        return True
    except Exception:
        return False


def send(text, items=None, last_id=None):
    token, chat, with_buttons = sender()
    wh = _send_webhook(text)
    if not token or not chat:
        if wh is None:
            return False, "нет токена/чата и ALERT_WEBHOOK_URL в конфиге"
        return bool(wh), ("ok (webhook)" if wh else "webhook failed")
    data = {"chat_id": chat, "parse_mode": "HTML", "text": text,
            "disable_web_page_preview": "true"}
    if with_buttons:
        km = keyboard(items or [], last_id)
        if km:
            data["reply_markup"] = km
    else:
        log("кнопки не прикреплены: отдельный бот охраны ещё не заведён "
            "(нет BTN_TG_TOKEN в /etc/mw-buttons.env) — сводка уходит от бота тревог")
    why = "не пробовали"
    for attempt in range(3):     # сеть может моргнуть — сводка важнее одной попытки
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=urllib.parse.urlencode(data).encode(),
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                d = json.load(r)
            if d.get("ok"):
                return True, "ok"
            why = str(d.get("description"))
        except Exception as e:  # noqa: BLE001 — важно не падать в таймере
            why = f"{type(e).__name__}: {e}"
        if attempt < 2:
            time.sleep(10 * (attempt + 1))
    return False, why


def log(msg):
    try:
        with open(DIGEST_LOG, "a") as f:
            f.write(f"{datetime.now(timezone.utc):%F %T} {msg}\n")
        os.chmod(DIGEST_LOG, 0o600)
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="не отправлять, только напечатать")
    ap.add_argument("--hours", type=float, help="окно в часах вместо «с прошлой сводки»")
    ap.add_argument("--stdout", action="store_true", help="печатать текст и при отправке")
    ap.add_argument("--force", action="store_true",
                    help="ручная отправка вне расписания (тихий режим всё равно уважается)")
    args = ap.parse_args()

    now = int(time.time())
    if args.hours:
        since = now - int(args.hours * 3600)
    else:
        try:
            since = int(open(LAST_RUN).read().strip())
        except (OSError, ValueError):
            since = now - WINDOW_H * 3600
        # защита от перекосов: не короче 6 ч и не длиннее 48 ч
        since = min(max(since, now - 48 * 3600), now - 6 * 3600)

    text, stats = build(now, since)
    dead = stats["stale"] or stats["dead"]

    if args.dry_run or args.stdout:
        print(text)
    if args.dry_run:
        return 0

    try:
        with open(LAST_TEXT, "w") as f:
            f.write(text)
        os.chmod(LAST_TEXT, 0o600)
    except OSError:
        pass

    mute_until = mute_state(now)
    if mute_until and not IGNORE_MUTE:
        log(f"ТИХИЙ РЕЖИМ до {mute_until}: сводка НЕ отправлена (DIGEST_IGNORE_MUTE=0), "
            f"текст сохранён в {LAST_TEXT}. Придержано: события сторожа={stats['mw']}, "
            f"срабатываний высшей важности={stats.get('crit')}, "
            f"заглушённых тревог={stats.get('muted')} (красных {stats.get('muted_red')})"
            + (", ОХРАНА НЕ ОТВЕЧАЕТ" if dead else ""))
        open(LAST_RUN, "w").write(str(now))
        return 0
    if mute_until and IGNORE_MUTE:
        log("тихий режим активен, но DIGEST_IGNORE_MUTE=1 — сводка отправляется")

    # Не уходить вне своего расписания: никаких догоняющих отправок пачкой
    # после простоя/перезагрузки. --force снимает проверку для ручного запуска.
    if not args.force:
        try:
            hh, mm = (int(x) for x in SCHEDULE_UTC.split(":"))
            sched = datetime.now(timezone.utc).replace(hour=hh, minute=mm, second=0, microsecond=0)
            drift = abs((datetime.now(timezone.utc) - sched).total_seconds()) / 60
            if drift > SEND_WINDOW_MIN:
                log(f"запуск вне расписания ({SCHEDULE_UTC} UTC ±{SEND_WINDOW_MIN} мин, "
                    f"отклонение {int(drift)} мин) — не отправляю, текст в {LAST_TEXT}. "
                    f"Ручная отправка: mw-digest.py --force")
                return 0
        except (ValueError, AttributeError):
            pass
    # одна сводка в сутки: если сегодня уже отправляли — второй раз не шлём
    try:
        prev = int(open(LAST_RUN).read().strip())
        if local(prev).date() == local(now).date() and not args.force:
            log("сводка за сегодня уже отправлялась — повтор не шлю")
            return 0
    except (OSError, ValueError):
        pass

    items = pending()
    ok, why = send(text, items, stats.get("last_id"))
    log(f"SEND ok={ok} ({why}) события: сторож={stats['mw']}, ловушки={stats['bait']}, "
        f"тревожно={stats['alarm']}, незакрытых изменений={len(items)}")
    if ok:
        open(LAST_RUN, "w").write(str(now))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
