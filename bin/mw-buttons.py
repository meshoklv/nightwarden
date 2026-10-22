#!/usr/bin/env python3
"""Кнопки под утренней сводкой и под тревогами охраны сервера.

⚠️ ЮНИТ mw-buttons.service НАМЕРЕННО ВЫКЛЮЧЕН (disabled). Причина ниже.

ПОЧЕМУ ВЫКЛЮЧЕН. Кнопки работают через Telegram long-poll (getUpdates), а
на один токен бота допустим только ОДИН такой опрос: если тот же бот уже
читает другая программа, получится вечная драка за поток и потеря
сообщений. Поэтому обработчик кнопок включается только с ОТДЕЛЬНЫМ ботом охраны.

КАК ВКЛЮЧИТЬ (когда заведён ОТДЕЛЬНЫЙ бот охраны):
  1) положить токен в /etc/mw-buttons.env (chmod 600):  BTN_TG_TOKEN=<токен>
  2) sudo systemctl enable --now mw-buttons.service
Больше ничего менять не надо: сводка сама увидит токен, начнёт уходить от имени
нового бота и прикрепит кнопки. (У кнопок Telegram отвечает ТОТ бот, который
отправил сообщение, — поэтому сводку должен слать он же.)

Режимы:
  mw-buttons.py keyboard [--aid AID --title T ...] [--last-id ID]
  mw-buttons.py serve                       — обработчик нажатий (systemd)
  mw-buttons.py handle FILE [--offline]     — обработать один callback_query (тест)

Кнопки (интерфейс сторожа):
  ✅ Норма: <что>  → malware-watch.sh accept <код>[,<код>…] <кто>
  ⏰ Отложить      → malware-watch.sh snooze <код>[,<код>…] <часов, по умолчанию 12>
  🔕 Тихо 8 часов  → /var/lib/malware-watch/mute := now+8h
  🔍 Подробности   → технические детали события
Полного сброса базы (baseline) кнопкой НЕТ и не будет.
Коды возврата сторожа: 0 — принято; 1 — не принято, состояние успели изменить;
75 — занято, повтори через минуту. 75 показываем как «повтори» и код НЕ гасим,
чтобы повторное нажатие сработало; выдать 75 за «принято» нельзя ни при каких условиях.

Права: сервис работает под root (systemd) и зовёт скрипт НАПРЯМУЮ.
Правило sudoers для бота НЕ заводим — оно ослабляет права машины и не нужно.

Безопасность:
  • команду выполняем ТОЛЬКО если callback_query.from.id == наш chat_id,
    чужие нажатия не выполняются и пишутся в журнал;
  • aid одноразовый: повторное или протухшее нажатие ничего не выполняет,
    в ответ «уже неактуально»;
  • кто нажал — уезжает в malware-watch.sh переменной окружения MW_BY.
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
from datetime import datetime, timedelta, timezone

ENV_FILE = os.environ.get("MWD_ENV", "/etc/malware-watch.env")
BTN_ENV_FILE = os.environ.get("MWD_BTN_ENV", "/etc/mw-buttons.env")
CONF_FILE = os.environ.get("MWD_CONF", "/etc/mw-digest.conf")
# пути переопределяются окружением — нужно для тестов, чтобы не трогать живое состояние
STATE_DIR = os.environ.get("MWD_STATE_DIR", "/var/lib/malware-watch")
MUTE_FILE = os.path.join(STATE_DIR, "mute")
OFFSET_FILE = os.path.join(STATE_DIR, "buttons-offset")
AID_USED = os.path.join(STATE_DIR, "aid-used.jsonl")
MW_EVENTS = os.environ.get("MWD_MW_EVENTS", "/var/log/malware-watch/events.jsonl")
BAIT_EVENTS = os.environ.get("MWD_BAIT_EVENTS", "/var/log/bait-watch/events.jsonl")
LOG = os.environ.get("MWD_BUTTONS_LOG", "/var/log/malware-watch/buttons.log")
INBOX = os.environ.get("MWD_INBOX", "/var/log/malware-watch/tg-inbox.jsonl")
MW_SCRIPT = os.environ.get("MWD_MW_SCRIPT", "/usr/local/sbin/malware-watch.sh")

MUTE_SECONDS = 8 * 3600
SNOOZE_HOURS = 12          # по умолчанию у сторожа именно 12
PLACEHOLDERS = {"", "СЮДА_ТОКЕН", "PUT_TOKEN_HERE", "<токен>"}

OFFLINE = False


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
BTN_ENV = load_env(BTN_ENV_FILE)
CONF = load_env(CONF_FILE)

# Токен ОТДЕЛЬНОГО бота охраны. Старый бот тревог не годится: его поток апдейтов
# занят чужими слушателями, а его токен когда-то лежал в мировочитаемом файле,
# то есть считается засвеченным и подлежит замене.
TOKEN = BTN_ENV.get("BTN_TG_TOKEN", "")
if TOKEN in PLACEHOLDERS:
    TOKEN = ""
CHAT = BTN_ENV.get("BTN_TG_CHAT") or ENV.get("TG_CHAT", "")
try:
    TZ = timezone(timedelta(hours=int(CONF.get("DIGEST_TZ_OFFSET", "0"))))
except ValueError:
    TZ = timezone(timedelta(hours=0))


def log(msg):
    line = f"{datetime.now(timezone.utc):%F %T} {msg}"
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
        os.chmod(LOG, 0o600)
    except OSError:
        pass
    print(line, flush=True)


def esc(s):
    return html.escape(str(s), quote=False)


# ─────────────────────────── клавиатура ───────────────────────────
def fit_codes(prefix, codes, suffix=""):
    """Уложить список кодов в лимит callback_data (64 байта), выбрасывая коды
    ЦЕЛИКОМ. Обрезать строку посередине нельзя: получится чужой/несуществующий код."""
    kept = []
    for c in [x for x in codes if x]:
        probe = prefix + ",".join(kept + [c]) + suffix
        if len(probe.encode()) > 64:
            break
        kept.append(c)
    return (prefix + ",".join(kept) + suffix) if kept else "", len(kept)


def keyboard(items=None, last_id=None):
    """items — [{'aid':..., 'title':...}] незакрытых изменений (из pending-json).

    На каждое изменение — своя кнопка «принять»: по контракту принимается ОДНО
    изменение по своему aid. Полного сброса базы кнопкой нет.
    """
    rows = []
    for it in (items or [])[:3]:
        aid = str(it.get("aid") or "")
        if not aid:
            continue
        title = str(it.get("title") or "изменение")
        if len(title) > 22:
            title = title[:21] + "…"
        cls = str(it.get("cls") or it.get("class") or "white").lower()
        codes = [c.strip() for c in aid.split(",") if c.strip()]
        acc_data, acc_n = fit_codes("a:", codes)
        snz_data, snz_n = fit_codes("s:", codes, f":{SNOOZE_HOURS}")
        if acc_n < len(codes):
            title = f"{title} ({acc_n} из {len(codes)})"
            if len(title) > 30:
                title = title[:29] + "…"
        row = []
        # КРАСНОЕ одной кнопкой с телефона «нормой» не объявляем: именно так настоящее
        # проникновение и получает штамп «всё в порядке». Красное можно только отложить.
        if cls != "red" and acc_data:
            row.append({"text": f"✅ Норма: {title}", "callback_data": acc_data})
        else:
            ev = str(it.get("id") or "")
            row.append({"text": f"🚨 {title}" if cls == "red" else f"ℹ️ {title}",
                        "callback_data": (f"d:{ev}"[:64] if ev else "d")})
        if snz_data:
            row.append({"text": "⏰ Отложить", "callback_data": snz_data})
        rows.append(row)
    rows.append([
        {"text": "🔕 Тихо 8 часов", "callback_data": "m8"},
        {"text": "🔍 Подробности",
         "callback_data": (f"d:{last_id}"[:64] if last_id else "d")},
    ])
    return {"inline_keyboard": rows}


# ─────────────────────────── Telegram ───────────────────────────
def api(method, **params):
    if OFFLINE:
        log(f"OFFLINE: пропущен вызов {method} {json.dumps(params, ensure_ascii=False)[:200]}")
        return {"ok": True, "offline": True}
    if not TOKEN:
        log(f"НЕТ ТОКЕНА бота охраны — вызов {method} невозможен")
        return {"ok": False, "description": "нет токена"}
    url = f"https://api.telegram.org/bot{TOKEN}/{method}"
    data = urllib.parse.urlencode(
        {k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v)
         for k, v in params.items() if v is not None}
    ).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:  # noqa: BLE001
            return {"ok": False, "error_code": e.code, "description": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "description": f"{type(e).__name__}: {e}"}


def say(text):
    return api("sendMessage", chat_id=CHAT, parse_mode="HTML", text=text,
               disable_web_page_preview="true")


# ─────────────────── одноразовые токены изменений ───────────────────
def aid_used(aid):
    try:
        with open(AID_USED) as f:
            for line in f:
                try:
                    if json.loads(line).get("aid") == aid:
                        return True
                except ValueError:
                    continue
    except OSError:
        pass
    return False


def aid_consume(aid, action, by):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(AID_USED, "a") as f:
            f.write(json.dumps({"aid": aid, "action": action, "by": by,
                                "ts": int(time.time())}, ensure_ascii=False) + "\n")
        os.chmod(AID_USED, 0o600)
    except OSError as e:
        log(f"не смог записать использованный aid: {e}")


STALE = ("🤷 <b>Уже неактуально</b>\n<blockquote>Эта кнопка устарела: изменение "
         "уже закрыто или сторож его больше не видит.</blockquote>")
CHANGED = ("↩️ <b>Не принял</b>\n<blockquote>Пока ты читал, на сервере успело измениться "
           "именно это место. Я НЕ стал записывать его как норму — посмотри свежую тревогу."
           "</blockquote>")
BUSY = ("⏳ <b>Сейчас занято</b>\n<blockquote>Сторож прямо сейчас работает. "
        "<b>Нажми ещё раз через минуту</b> — я ничего не записал.</blockquote>")
RED_REFUSED = ("🚨 <b>Красное кнопкой не закрываю</b>\n<blockquote>Это тревога высшей "
               "важности. Такие принимают только руками с консоли и осознанно — чтобы "
               "настоящее проникновение нельзя было узаконить одним касанием с телефона.\n"
               "Нажми <b>«Подробности»</b> и посмотри, что там.</blockquote>")
RC_BUSY = 75          # «повтори через минуту» — НИ В КОЕМ СЛУЧАЕ не выдавать за «принято»
RC_CHANGED = 1        # «не принято, состояние успели изменить»
RC_REFUSED = 2        # красное (кнопкой нельзя) ЛИБО мусорный код — различаем по тексту
RED_RE = re.compile(r"КРАСНА|ОТКАЗ", re.I)


# ─────────────────────────── действия кнопок ───────────────────────────
def run_mw(args):
    """Запуск malware-watch.sh НАПРЯМУЮ.

    Сервис работает под root (systemd), поэтому sudo не нужен. Правило sudoers
    для бота специально НЕ заводим: она сама по себе ослабляет права машины и
    поднимает тревогу у сторожа, а надобности в ней нет.
    """
    if os.geteuid() != 0:
        log("обработчик запущен НЕ под root — команду сторожу не отдаю. "
            "Он должен работать systemd-сервисом под root; sudoers не заводим.")
        return 126, "", "нужен root"
    cmd = [MW_SCRIPT] + [str(a) for a in args]
    if OFFLINE:
        log(f"OFFLINE: выполнил бы {' '.join(cmd)}")
        return 0, "offline", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", str(e)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def act_accept(aid, by):
    """aid — один код или несколько через запятую (одна строка сводки часто
    относится к нескольким изменениям)."""
    if not aid or aid_used(aid):
        log(f"ACCEPT отклонён: aid={aid!r} уже использован или пуст — ничего не выполняю")
        return STALE, False, "Уже неактуально"
    rc, out, err = run_mw(["accept", aid, by])      # «кто» — позиционным аргументом
    log(f"ACCEPT коды={aid} кто={by} rc={rc} out={out[:200]} err={err[:200]}")
    if rc == RC_BUSY:
        return BUSY, False, "Занято — нажми ещё раз через минуту"
    if rc == RC_CHANGED:
        return CHANGED, False, "Не принял: изменилось"
    if rc == RC_REFUSED and RED_RE.search(out + err):
        return RED_REFUSED, False, "Красное кнопкой не принимают"
    if rc != 0:
        return STALE, False, "Уже неактуально"
    aid_consume(aid, "accept", by)
    n = len([x for x in aid.split(",") if x])
    what = "это изменение" if n == 1 else f"эти {n} изменения"
    return (f"✅ <b>Принял</b>\n<blockquote>Записал {what} как нормальные. "
            f"Про них больше не напишу.</blockquote>"), True, "Принято"


def act_snooze(aid, hours, by):
    if not aid or aid_used(aid):
        log(f"SNOOZE отклонён: aid={aid!r} уже использован или пуст — ничего не выполняю")
        return STALE, False, "Уже неактуально"
    rc, out, err = run_mw(["snooze", aid, str(hours)])
    log(f"SNOOZE коды={aid} часов={hours} кто={by} rc={rc} out={out[:200]} err={err[:200]}")
    if rc == RC_BUSY:
        return BUSY, False, "Занято — нажми ещё раз через минуту"
    if rc == RC_CHANGED:
        return CHANGED, False, "Не отложил: изменилось"
    if rc != 0:
        return STALE, False, "Уже неактуально"
    aid_consume(aid, "snooze", by)
    return (f"⏰ <b>Отложил на {hours} ч</b>\n<blockquote>Вернусь к этому позже. Если ничего "
            f"не изменится — напомню в утренней сводке.</blockquote>"), True, "Отложено"


def act_mute8(by):
    until = int(time.time()) + MUTE_SECONDS
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(MUTE_FILE, "w") as f:
            f.write(str(until))
    except OSError as e:
        log(f"MUTE ошибка: {e}")
        return f"⚠️ не смог включить тишину: {esc(e)}", False, "Не вышло"
    log(f"MUTE до {until} by={by}")
    when = datetime.fromtimestamp(until, TZ).strftime("%d.%m %H:%M")
    return ("🔕 <b>Тихо на 8 часов</b>\n<blockquote>Не побеспокою до <b>" + when +
            "</b>. Охрана продолжает работать и всё пишет в журнал — "
            "утренняя сводка расскажет, что было.</blockquote>"), True, "Тихо 8 часов"


def _last_json(path):
    """Последняя валидная запись jsonl без чтения файла целиком."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - 65536))
            tail = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    for line in reversed(tail):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def _find_event(ev_id):
    """Событие по короткому id из контракта. Читаем только хвост файла."""
    if not ev_id:
        return None
    try:
        size = os.path.getsize(MW_EVENTS)
        with open(MW_EVENTS, "rb") as f:
            f.seek(max(0, size - 400000))
            tail = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    for line in reversed(tail):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("id") == ev_id:
            return d
    return None


def act_details(ev_id=None):
    mw = _find_event(ev_id) or _last_json(MW_EVENTS)
    bait = _last_json(BAIT_EVENTS)
    parts = ["🔍 <b>Технические подробности</b>"]
    if mw:
        det = re.sub(r"<[^>]+>", "", mw.get("detail", "") or "").strip()
        head = f"\n🛡 <b>Сторож</b> · <i>{esc(mw.get('ts', '?'))} UTC · {esc(mw.get('sev', '?'))}</i>"
        if mw.get("id"):
            head += f" · <code>{esc(mw['id'])}</code>"
        parts.append(head)
        parts.append(f"<blockquote>{esc(mw.get('title') or mw.get('kind', '?'))}\n"
                     f"{esc(det[:900])}</blockquote>")
    if bait:
        proc = bait.get("proc") or {}
        parts.append(f"\n🪤 <b>Ловушка</b> · <i>{esc(bait.get('ts_iso', '?'))}</i>")
        body = [
            f"файл: {esc(bait.get('bait', '?'))}",
            f"кто: {esc((proc.get('cmdline') or '?')[:200])}",
            f"где: {esc(proc.get('where') or proc.get('container') or '?')}",
            f"цепочка: {esc((proc.get('parents') or '?')[:250])}",
        ]
        if bait.get("reason"):
            body.append(f"вывод: {esc(bait['reason'])}")
        parts.append("<blockquote>" + "\n".join(body) + "</blockquote>")
    if not mw and not bait:
        parts.append("<blockquote>Журналы пустые — событий нет.</blockquote>")
    return "\n".join(parts)[:4000], True, "Показываю"


# ─────────────────────────── обработка нажатия ───────────────────────────
def handle_callback(cq):
    cq_id = cq.get("id")
    frm = cq.get("from") or {}
    uid = str(frm.get("id", ""))
    data = cq.get("data") or ""
    who = frm.get("username") or frm.get("first_name") or "?"

    if not CHAT or uid != str(CHAT):
        log(f"ЧУЖОЕ НАЖАТИЕ ОТКЛОНЕНО: id={uid} username={who} data={data!r} — команда НЕ выполнена")
        api("answerCallbackQuery", callback_query_id=cq_id,
            text="Эта кнопка не для вас.", show_alert="true")
        return "rejected"

    log(f"НАЖАТИЕ принято: id={uid} data={data}")
    parts = data.split(":")
    if parts[0] == "a":
        text, ok, toast = act_accept(parts[1] if len(parts) > 1 else "", uid)
    elif parts[0] == "s":
        aid = parts[1] if len(parts) > 1 else ""
        hours = parts[2] if len(parts) > 2 and parts[2].isdigit() else str(SNOOZE_HOURS)
        text, ok, toast = act_snooze(aid, hours, uid)
    elif data == "m8":
        text, ok, toast = act_mute8(uid)
    elif parts[0] == "d":
        text, ok, toast = act_details(parts[1] if len(parts) > 1 else None)
    else:
        log(f"неизвестная кнопка data={data!r} от {uid}")
        api("answerCallbackQuery", callback_query_id=cq_id, text="Кнопка устарела.")
        return "unknown"

    # всплывашка обязана совпадать по смыслу с сообщением: «занято» не должно
    # выглядеть ни как «принято», ни как «неактуально»
    api("answerCallbackQuery", callback_query_id=cq_id, text=toast)
    say(text)
    return "done" if ok else "stale"


def save_message(msg):
    """Входящие сообщения кладём в журнал, чтобы они не терялись."""
    rec = {
        "ts": msg.get("date"),
        "chat": (msg.get("chat") or {}).get("id"),
        "from": (msg.get("from") or {}).get("username"),
        "text": msg.get("text") or msg.get("caption"),
        "update_source": "mw-buttons",
    }
    try:
        with open(INBOX, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.chmod(INBOX, 0o600)
    except OSError:
        pass


# ─────────────────────────── цикл ───────────────────────────
def serve():
    if not TOKEN:
        log(f"НЕТ токена бота охраны в {BTN_ENV_FILE} (BTN_TG_TOKEN) — обработчик не запускается. "
            f"Заведи ОТДЕЛЬНОГО бота у BotFather, положи токен в этот файл (chmod 600), "
            f"затем: systemctl enable --now mw-buttons.service")
        return 1
    try:
        offset = int(open(OFFSET_FILE).read().strip())
    except (OSError, ValueError):
        offset = 0
    log(f"старт обработчика кнопок (отдельный бот охраны), offset={offset}")
    while True:
        d = api("getUpdates", offset=offset, timeout=45,
                allowed_updates=["callback_query", "message"])
        if not d.get("ok"):
            if d.get("error_code") == 409:
                # На СВОЁМ боте этого быть не должно — значит, запущен второй экземпляр
                # сервиса или бота опрашивает кто-то ещё. Второй long-poll не плодим.
                log("409 на собственном боте: кто-то ещё опрашивает его. Останавливаюсь, "
                    "чтобы не драться за поток — разберись, кто это, и запусти заново.")
                return 1
            log(f"ошибка опроса: {d.get('description')}")
            time.sleep(5)
            continue
        for u in d.get("result", []):
            offset = u["update_id"] + 1
            try:
                if "callback_query" in u:
                    handle_callback(u["callback_query"])
                elif "message" in u:
                    save_message(u["message"])
            except Exception as e:  # noqa: BLE001 — сервис не должен умирать от одного апдейта
                log(f"сбой обработки апдейта {u.get('update_id')}: {type(e).__name__}: {e}")
        try:
            with open(OFFSET_FILE, "w") as f:
                f.write(str(offset))
        except OSError:
            pass


def main():
    global OFFLINE
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="serve", choices=["serve", "keyboard", "handle"])
    ap.add_argument("file", nargs="?", help="файл с callback_query (режим handle)")
    ap.add_argument("--aid", action="append", default=[], help="aid незакрытого изменения")
    ap.add_argument("--title", action="append", default=[], help="его название (в том же порядке)")
    ap.add_argument("--cls", action="append", default=[],
                    help="важность red|amber|white (в том же порядке)")
    ap.add_argument("--id", action="append", default=[],
                    help="id события (в том же порядке)")
    ap.add_argument("--last-id", help="id последнего события для кнопки «Подробности»")
    ap.add_argument("--offline", action="store_true",
                    help="не ходить в Telegram и не выполнять команды (тест)")
    args = ap.parse_args()
    OFFLINE = args.offline

    if args.mode == "keyboard":
        items = [{"aid": a,
                  "title": (args.title[i] if i < len(args.title) else "изменение"),
                  "cls": (args.cls[i] if i < len(args.cls) else "white"),
                  "id": (args.id[i] if i < len(args.id) else "")}
                 for i, a in enumerate(args.aid)]
        print(json.dumps(keyboard(items, args.last_id), ensure_ascii=False))
        return 0
    if args.mode == "handle":
        if not args.file:
            print("нужен файл с callback_query", file=sys.stderr)
            return 2
        with open(args.file) as f:
            cq = json.load(f)
        print(handle_callback(cq.get("callback_query", cq)))
        return 0
    return serve()


if __name__ == "__main__":
    sys.exit(main())
