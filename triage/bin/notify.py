#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
notify.py -- the ONLY place where the triage talks to a human.

Why a separate file, not part of the triage daemon:
  The triaging Claude reads text that is partly written by the ATTACKER
  (file names, command lines). So it must never be allowed near the sending
  code. It returns JSON of a strictly fixed shape; the message text is built
  by THIS script from a rigid template. Even a fully hijacked model can only
  put words inside a ready-made frame -- it cannot write to a third party,
  run a command, or change the recipient.

NO BOT TOKEN IS STORED HERE. For the telegram sink it is read from the guard's
env file (default /etc/malware-watch.env, variables TG_TOKEN / TG_CHAT), so
rotating the bot token means zero edits here: the guard and the triage always
talk through the same bot.

Default SINK=file -- NOTHING is sent to a human, messages are appended to a
file. Real delivery needs an explicit TRIAGE_SINK=telegram or =webhook.

Language of the fixed message templates: TRIAGE_LANG=en|ru (default en).
"""
import json
import os
import re
import socket
import sys
import time
import html
import urllib.parse
import urllib.request

CONF = os.environ.get("TRIAGE_CONF", "/etc/alert-triage.env")


def load_env_file(path):
    """Reads KEY=VALUE lines. Never prints values."""
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


CFG = load_env_file(CONF)


def cfg(key, default=""):
    return os.environ.get(key, CFG.get(key, default))


SINK = cfg("TRIAGE_SINK", "file")                 # file | stdout | telegram | webhook
OUTBOX = cfg("TRIAGE_OUTBOX", "/var/log/alert-triage/outbox.jsonl")
SENTLOG = cfg("TRIAGE_SENTLOG", "/var/log/alert-triage/sent.jsonl")
TG_ENV_FILE = cfg("TRIAGE_TG_ENV_FILE", "/etc/malware-watch.env")
TG_TOKEN_VAR = cfg("TRIAGE_TG_TOKEN_VAR", "TG_TOKEN")
TG_CHAT_VAR = cfg("TRIAGE_TG_CHAT_VAR", "TG_CHAT")
WEBHOOK_URL = cfg("TRIAGE_WEBHOOK_URL", "")       # no default on purpose
WEBHOOK_TIMEOUT_S = 10
MUTE_FILE = cfg("TRIAGE_MUTE_FILE", "/var/lib/malware-watch/mute")

MAXLEN = 3900  # Telegram limit is 4096; keep headroom for the footer

LANG = cfg("TRIAGE_LANG", "en").strip().lower()
if LANG not in ("en", "ru"):
    LANG = "en"

# ───────────────────── FIXED TEXT, PER LANGUAGE ─────────────────────
# Keys are used by the templates below and by triage-daemon.py (via T()).
STR = {
    "en": {
        "ack_head": "👀 <b>Alert seen, looking into it</b>",
        "ack_alert": "Alert",
        "ack_wait": "I am checking what this is -- an answer in a couple of minutes",
        "ack_readonly": "I touch nothing meanwhile: the analysis is <b>read-only</b>",
        "case": "case",
        "guard": "guard",
        "confidence": "confidence",
        "readonly_tail": "read-only analysis",
        "v_false_alarm": "🟢 <b>False alarm</b>",
        "v_real_attack": "🔴 <b>Looks like a real intrusion</b>",
        "v_needs_human": "🟠 <b>Needs your eyes</b>",
        "v_undetermined": "⚪ <b>Could not work it out</b>",
        "sec_what": "🔍 <b>What happened</b>",
        "sec_why": "🧾 <b>Why I decided so</b>",
        "sec_threat": "⚠️ <b>What it threatens</b>",
        "sec_guard": "🛡 <b>What the guard already did by itself</b>",
        "sec_steps": "🚀 <b>What you should do</b>",
        "disagree_head": "❗️ <b>Careful: I may be wrong</b>",
        "disagree_body": ("The guard rates this <b>red</b> (proven intrusion), "
                          "and I called it a false alarm. Trust the guard, not me: "
                          "re-check by hand."),
        "inj_head": "🪤 <b>The alert text contained command-like lines</b>",
        "inj_body": ("Someone may have tried to trick the analysis itself. "
                     "I did not follow them, but trust the conclusions above "
                     "less than usual."),
        "sec_raw_long": "📄 <b>Alert verbatim, as the guard saw it</b>",
        "sec_raw": "📄 <b>Alert verbatim</b>",
        "f_head": "⚪ <b>Analysis failed</b>",
        "f_sub": "The alert is real; it is my analysis that broke -- look yourself.",
        "f_what": "🔧 <b>What went wrong</b>",
        "storm_head": "🌩 <b>Many alerts at once -- analysing as one batch</b>",
        "storm_1": "In the last <b>%d min</b> there were <b>%d</b> alerts",
        "storm_2": "I will not analyse them one by one -- this is a storm, not events",
        "storm_3": "One combined analysis follows",
        "cap_head": "🧯 <b>Analyses paused</b>",
        "cap_1": "Hit a ceiling: <b>%s</b>",
        "cap_2": "Guard alerts continue as usual -- only the automatic analysis is silent",
        "cap_3": "Lift the ceiling: <code>systemctl restart alert-triage</code>",
        "unknown_alert": "alert",
        # daemon-side fixed strings (also logged)
        "gate_self": "traces of the triage's own work",
        "gate_dedup": "the same alert was analysed %d min ago",
        "gate_gap": "less than %d s since the previous analysis",
        "gate_hour": "per-hour analysis ceiling (%d)",
        "gate_day": "per-day analysis ceiling (%d)",
        "gate_usd": "daily spend ceiling ($%.2f)",
        "err_timeout": "analysis did not finish within %d seconds",
        "err_start": "could not start the analysis (%s)",
        "err_badout": "analysis returned something unexpected",
        "err_isError": "analysis ended with an error (%s)",
        "err_freetext": "analysis answered in free text instead of the required shape",
        "err_noverdict": "the analysis answer has no verdict",
        "guard_facts": ("Class computed by the guard with no model at all: %s\n"
                        "Alert fingerprint: %s\n"
                        "Quiet mode now: %s\n"),
        "yes": "yes",
        "no": "no",
    },
    "ru": {
        "ack_head": "👀 <b>Вижу тревогу, разбираюсь</b>",
        "ack_alert": "Тревога",
        "ack_wait": "Я смотрю, что это такое — ответ будет через пару минут",
        "ack_readonly": "Пока ничего не трогаю: разбор работает <b>только на просмотр</b>",
        "case": "дело",
        "guard": "охрана",
        "confidence": "уверенность",
        "readonly_tail": "разбор только на просмотр",
        "v_false_alarm": "🟢 <b>Ложная тревога</b>",
        "v_real_attack": "🔴 <b>Похоже на настоящее вторжение</b>",
        "v_needs_human": "🟠 <b>Нужен твой взгляд</b>",
        "v_undetermined": "⚪ <b>Не смог разобрать</b>",
        "sec_what": "🔍 <b>Что случилось</b>",
        "sec_why": "🧾 <b>Почему я так решил</b>",
        "sec_threat": "⚠️ <b>Чем это грозит</b>",
        "sec_guard": "🛡 <b>Что охрана уже сделала сама</b>",
        "sec_steps": "🚀 <b>Что сделать тебе</b>",
        "disagree_head": "❗️ <b>Осторожно: я мог ошибиться</b>",
        "disagree_body": ("Охрана считает это <b>красным</b> (доказанное вторжение), "
                          "а я назвал ложной тревогой. Верь охране, а не мне: "
                          "перепроверь руками."),
        "inj_head": "🪤 <b>В тексте тревоги были похожие на команды строки</b>",
        "inj_body": ("Кто-то мог пытаться обмануть сам разбор. "
                     "Я их не выполнял, но выводам ниже доверяй меньше обычного."),
        "sec_raw_long": "📄 <b>Тревога дословно, как её увидела охрана</b>",
        "sec_raw": "📄 <b>Тревога дословно</b>",
        "f_head": "⚪ <b>Разобрать не получилось</b>",
        "f_sub": "Тревога настоящая, а вот мой разбор сорвался — смотри сам.",
        "f_what": "🔧 <b>Что пошло не так</b>",
        "storm_head": "🌩 <b>Тревог сразу много — разбираю пачкой</b>",
        "storm_1": "За последние <b>%d мин</b> пришло <b>%d</b> тревог",
        "storm_2": "По одной разбирать не буду — это шторм, а не события",
        "storm_3": "Один общий разбор пришлю следом",
        "cap_head": "🧯 <b>Разборы приостановлены</b>",
        "cap_1": "Упёрся в потолок: <b>%s</b>",
        "cap_2": "Тревоги охраны идут как обычно — молчит только автоматический разбор",
        "cap_3": "Снять потолок: <code>systemctl restart alert-triage</code>",
        "unknown_alert": "тревога",
        "gate_self": "это следы работы самого разбора",
        "gate_dedup": "такую же тревогу разбирали %d мин назад",
        "gate_gap": "меньше %d с с прошлого разбора",
        "gate_hour": "потолок разборов в час (%d)",
        "gate_day": "потолок разборов в сутки (%d)",
        "gate_usd": "потолок трат в сутки ($%.2f)",
        "err_timeout": "разбор не уложился в %d секунд",
        "err_start": "не смог запустить разбор (%s)",
        "err_badout": "разбор вернул не то, что ожидалось",
        "err_isError": "разбор закончился ошибкой (%s)",
        "err_freetext": "разбор ответил свободным текстом вместо ответа заданной формы",
        "err_noverdict": "в ответе разбора нет вердикта",
        "guard_facts": ("Класс, посчитанный охраной без всякой модели: %s\n"
                        "Отпечаток тревоги: %s\n"
                        "Тихий режим сейчас: %s\n"),
        "yes": "да",
        "no": "нет",
    },
}


def T(key):
    """Fixed text in the configured language (falls back to English)."""
    return STR.get(LANG, STR["en"]).get(key) or STR["en"].get(key, key)


def muted_now():
    """Guard quiet mode. Uncertainty is resolved IN FAVOUR OF SILENCE, as in
    the guard itself: if the file exists but cannot be read, assume quiet."""
    try:
        if os.path.exists(MUTE_FILE) and not os.access(MUTE_FILE, os.R_OK):
            return True
        with open(MUTE_FILE, "r") as f:
            raw = f.read().strip()
        return raw.isdigit() and int(raw) > time.time()
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _append(path, obj):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except OSError as e:
        print("notify: could not write %s: %s" % (path, e), file=sys.stderr)


def to_plain(text):
    """HTML message -> plain text for the webhook: tags removed, entities
    (&lt; &gt; &amp; ...) decoded."""
    return html.unescape(re.sub(r"<[^>]*>", "", text))


def _send_telegram(text, rec):
    tg = load_env_file(TG_ENV_FILE)
    token = tg.get(TG_TOKEN_VAR, "")
    chat = tg.get(TG_CHAT_VAR, "")
    if not token or not chat:
        rec["result"] = "no-token"
        return
    data = urllib.parse.urlencode({
        "chat_id": chat, "text": text[:MAXLEN], "parse_mode": "HTML",
        "disable_web_page_preview": "true"}).encode()
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    try:
        with urllib.request.urlopen(url, data=data, timeout=20) as r:
            ok = b'"ok":true' in r.read()
        rec["result"] = "sent" if ok else "rejected"
    except Exception as e:                                   # noqa: BLE001
        rec["result"] = "error"
        rec["error"] = type(e).__name__      # the error text may carry the token


def _send_webhook(text, rec):
    """POST {"text": plain, "content": plain} as JSON (works for Slack-style
    'text' and Discord-style 'content' endpoints). Never raises."""
    if not WEBHOOK_URL.lower().startswith(("http://", "https://")):
        rec["result"] = "no-url"
        return
    plain = to_plain(text)
    body = json.dumps({"text": plain, "content": plain},
                      ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        WEBHOOK_URL, data=body, method="POST",
        headers={"Content-Type": "application/json; charset=utf-8",
                 "User-Agent": "nightwarden-triage"})
    try:
        with urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT_S) as r:
            code = r.getcode()
        rec["result"] = "sent" if 200 <= code < 300 else "rejected"
    except Exception as e:                                   # noqa: BLE001
        rec["result"] = "error"
        # the URL itself usually is the secret -- log the exception type only
        rec["error"] = type(e).__name__
        print("notify: webhook delivery failed (%s)" % type(e).__name__,
              file=sys.stderr)


def deliver(text, case_id="", kind="triage", force=False):
    """force=True is only for the 'guard death' class: it must break quiet mode."""
    rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
           "case": case_id, "kind": kind, "sink": SINK, "len": len(text)}

    if muted_now() and not force:
        rec["result"] = "muted"
        rec["text"] = text
        _append(OUTBOX, rec)
        return "muted"

    if SINK == "stdout":
        print(text)
        rec["result"] = "stdout"
        _append(SENTLOG, rec)
        return "stdout"

    if SINK not in ("telegram", "webhook"):
        rec["result"] = "file"
        rec["text"] = text
        _append(OUTBOX, rec)
        return "file"

    if SINK == "telegram":
        _send_telegram(text, rec)
    else:
        _send_webhook(text, rec)
    if rec["result"] != "sent":
        rec["text"] = text
        _append(OUTBOX, rec)
    _append(SENTLOG, rec)
    return rec["result"]


# ──────────────────────────── MESSAGE TEMPLATES ────────────────────────────
# The shape of the messages is FIXED here. The model cannot change it: it only
# fills the marked places, and each of them is escaped.

def e(s, limit=1200):
    return html.escape(str(s or "")[:limit], quote=False)


def _host():
    try:
        return socket.gethostname()[:40]
    except OSError:
        return "host"


def msg_ack(alert_title, case_id):
    """'I am here, looking' -- goes out IMMEDIATELY, WITHOUT the model.
    A human must not be left alone with a scary message while the analysis is
    thinking. The text is fixed; nothing can be injected into it."""
    return ("%s\n"
            "<blockquote>• %s: <b>%s</b>\n"
            "• %s\n"
            "• %s</blockquote>\n"
            "<i>%s %s · %s</i>" % (
                T("ack_head"), T("ack_alert"), e(alert_title, 200),
                T("ack_wait"), T("ack_readonly"),
                T("case"), e(case_id, 40), e(_host(), 40)))


def msg_verdict(v, alert_raw, det_class, case_id, cost=None, model=""):
    """The result. Three things are MANDATORY here and do not depend on the model:
       1) the original alert text, verbatim, so the human can disbelieve me;
       2) the class computed WITHOUT the model -- if the model and the class
          disagree, it shows right in the message;
       3) the case id -- the whole model transcript can be found by it."""
    verdict = str(v.get("verdict", "undetermined"))
    conf = str(v.get("confidence", "low"))
    head = T("v_" + verdict) if verdict in (
        "false_alarm", "real_attack", "needs_human", "undetermined"
    ) else T("v_undetermined")

    parts = [head]
    if v.get("one_liner"):
        parts.append("<i>%s</i>" % e(v["one_liner"], 300))
    parts.append("")

    if v.get("what_happened"):
        parts.append("%s\n<blockquote>%s</blockquote>"
                     % (T("sec_what"), e(v["what_happened"], 900)))
    if v.get("why_this_verdict"):
        parts.append("%s\n<blockquote>%s</blockquote>"
                     % (T("sec_why"), e(v["why_this_verdict"], 900)))
    if verdict != "false_alarm" and v.get("threat"):
        parts.append("%s\n<blockquote>%s</blockquote>"
                     % (T("sec_threat"), e(v["threat"], 600)))
    if v.get("already_done_by_guard"):
        parts.append("%s\n<blockquote>%s</blockquote>"
                     % (T("sec_guard"), e(v["already_done_by_guard"], 600)))

    steps = v.get("human_should") or []
    if isinstance(steps, list) and steps:
        body = "\n".join("• %s" % e(s, 300) for s in steps[:6])
        parts.append("%s\n<blockquote>%s</blockquote>" % (T("sec_steps"), body))

    # ── model disagrees with the guard's arithmetic: ALWAYS shown ──
    if det_class == "red" and verdict == "false_alarm":
        parts.append("%s\n<blockquote>%s</blockquote>"
                     % (T("disagree_head"), T("disagree_body")))
    if v.get("injection_suspected"):
        parts.append("%s\n<blockquote>%s</blockquote>"
                     % (T("inj_head"), T("inj_body")))

    parts.append("%s\n<blockquote>%s</blockquote>"
                 % (T("sec_raw_long"), e(alert_raw, 700)))

    tail = "%s %s · %s: %s · %s: %s · %s" % (
        T("case"), e(case_id, 40), T("guard"), e(det_class, 20),
        T("confidence"), e(conf, 20), T("readonly_tail"))
    if model:
        tail += " · %s" % e(model, 40)
    if cost is not None:
        tail += " · $%.3f" % cost
    parts.append("<i>%s</i>" % tail)
    return "\n".join(parts)


def msg_failed(alert_raw, det_class, case_id, reason):
    """The analysis failed. Silence is not allowed: the human already got 'looking'."""
    return ("%s\n"
            "<i>%s</i>\n\n"
            "%s\n<blockquote>%s</blockquote>\n"
            "%s\n<blockquote>%s</blockquote>\n"
            "<i>%s %s · %s: %s</i>"
            % (T("f_head"), T("f_sub"), T("f_what"), e(reason, 300),
               T("sec_raw"), e(alert_raw, 700),
               T("case"), e(case_id, 40), T("guard"), e(det_class, 20)))


def msg_storm(n, window_min, case_id):
    return ("%s\n"
            "<blockquote>• " + T("storm_1") + "\n"
            "• %s\n"
            "• %s</blockquote>\n"
            "<i>%s %s · %s</i>") % (
                T("storm_head"), window_min, n, T("storm_2"), T("storm_3"),
                T("case"), e(case_id, 40), e(_host(), 40))


def msg_capped(kind, case_id):
    return ("%s\n"
            "<blockquote>• " + T("cap_1") + "\n"
            "• %s\n"
            "• %s</blockquote>\n"
            "<i>%s %s · %s</i>") % (
                T("cap_head"), e(kind, 120), T("cap_2"), T("cap_3"),
                T("case"), e(case_id, 40), e(_host(), 40))


if __name__ == "__main__":
    # Manual check: echo '<b>test</b>' | notify.py --kind test
    kind = "manual"
    if "--kind" in sys.argv:
        kind = sys.argv[sys.argv.index("--kind") + 1]
    text = sys.stdin.read()
    print(deliver(text, case_id="manual", kind=kind))
