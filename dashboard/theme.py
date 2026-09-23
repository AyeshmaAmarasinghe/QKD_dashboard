"""Shared look and feel: dark navy header, light body, blue controls, white cards.

Kept deliberately small.  Layout uses native Streamlit containers and columns;
CSS only sets colours, spacing and badge shapes, so nothing depends on fragile
selectors for the page to remain usable.
"""
from __future__ import annotations

import html

import streamlit as st

NAVY = "#12203a"
NAVY_2 = "#1b2d4d"
BLUE = "#2563eb"
INK = "#0f172a"
MUTED = "#5b6780"
LINE = "#dbe2ef"
BG = "#f4f6fb"

STATUS_COLOURS = {
    "READY": ("#065f46", "#d1fae5"),
    "ACTIVE": ("#065f46", "#d1fae5"),
    "ACCEPTED": ("#065f46", "#d1fae5"),
    "AVAILABLE": ("#1e40af", "#dbeafe"),
    "DELIVERED": ("#065f46", "#d1fae5"),
    "DEGRADED": ("#92400e", "#fef3c7"),
    "CONSUMED": ("#334155", "#e2e8f0"),
    "RESERVED": ("#334155", "#e2e8f0"),
    "GENERATED": ("#334155", "#e2e8f0"),
    "PENDING": ("#92400e", "#fef3c7"),
    "EXPIRED": ("#92400e", "#fef3c7"),
    "REVOKED": ("#9f1239", "#ffe4e6"),
    "DESTROYED": ("#334155", "#e2e8f0"),
    "ABORTED": ("#9f1239", "#ffe4e6"),
    "UNAVAILABLE": ("#9f1239", "#ffe4e6"),
    "BLOCKED": ("#9f1239", "#ffe4e6"),
    "NO ACTION": ("#334155", "#e2e8f0"),
    "ALERT RAISED": ("#92400e", "#fef3c7"),
    "REKEYED": ("#1e40af", "#dbeafe"),
    "ARMED": ("#1e40af", "#dbeafe"),
    "FAILED": ("#9f1239", "#ffe4e6"),
    "DEFERRED": ("#92400e", "#fef3c7"),
    "COMPLETE": ("#065f46", "#d1fae5"),
    "NOT": ("#334155", "#e2e8f0"),
    "EVE": ("#334155", "#e2e8f0"),
    "ABOVE": ("#92400e", "#fef3c7"),
    "QKD": ("#1e40af", "#dbeafe"),
    "NETWORK": ("#065f46", "#d1fae5"),
}

CSS = f"""
<style>
  .stApp {{ background: {BG}; }}
  .block-container {{ padding-top: 3.2rem; padding-bottom: 3rem; max-width: 1500px; }}

  .qkd-header {{
      background: {NAVY}; color: #fff; border-radius: 12px;
      padding: 14px 20px; margin-bottom: 14px;
      display: flex; flex-wrap: wrap; gap: 10px 18px; align-items: center;
  }}
  .qkd-header .brand {{ font-weight: 700; font-size: 1.05rem; letter-spacing: .2px; }}
  .qkd-header .chip {{
      background: {NAVY_2}; border: 1px solid #2c3f63; border-radius: 999px;
      padding: 4px 12px; font-size: .78rem; font-family: ui-monospace, Menlo, monospace;
      color: #d8e2f5; white-space: nowrap;
  }}
  .qkd-header .spacer {{ flex: 1 1 auto; }}

  .qkd-card {{
      background: #fff; border: 1px solid {LINE}; border-radius: 12px;
      padding: 14px 16px; height: 100%;
      box-shadow: 0 1px 2px rgba(15,23,42,.04);
  }}
  .qkd-card .label {{
      font-size: .72rem; letter-spacing: .08em; text-transform: uppercase;
      color: {MUTED}; font-weight: 700; margin-bottom: 6px;
  }}
  .qkd-card .value {{
      font-size: 1.7rem; font-weight: 700; color: {INK}; line-height: 1.15;
      word-break: break-word;
  }}
  .qkd-card .value.small {{ font-size: 1.15rem; }}
  .qkd-card .unit {{ font-size: .85rem; color: {MUTED}; font-weight: 600; margin-left: 4px; }}
  .qkd-card .sub {{ font-size: .78rem; color: {MUTED}; margin-top: 8px; line-height: 1.35; }}

  .qkd-badge {{
      display: inline-block; border-radius: 999px; padding: 2px 10px;
      font-size: .72rem; font-weight: 700; letter-spacing: .04em;
      white-space: nowrap; word-break: keep-all;
  }}

  .qkd-note {{
      background: #eef2fb; border: 1px solid #d7e0f4; border-left: 4px solid {BLUE};
      border-radius: 8px; padding: 10px 14px; font-size: .85rem; color: #29344d;
  }}
  .qkd-warn {{
      background: #fff7ed; border: 1px solid #fed7aa; border-left: 4px solid #d97706;
      border-radius: 8px; padding: 10px 14px; font-size: .85rem; color: #7c2d12;
  }}

  .qkd-stage {{
      background: #fff; border: 1px solid {LINE}; border-radius: 10px;
      padding: 10px 12px; font-size: .8rem; height: 100%;
  }}
  .qkd-stage .n {{ font-size: .68rem; color: {MUTED}; letter-spacing: .08em;
                   text-transform: uppercase; font-weight: 700; }}
  .qkd-stage .t {{ font-weight: 700; color: {INK}; margin: 3px 0; }}

  .stButton > button[kind="primary"] {{
      background: {BLUE}; border-color: {BLUE}; font-weight: 600;
  }}
  section[data-testid="stSidebar"] {{ background: #fff; border-right: 1px solid {LINE}; }}
  div[data-testid="stDataFrame"] {{ border: 1px solid {LINE}; border-radius: 10px; }}
  footer {{ visibility: hidden; }}
</style>
"""


def inject() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def esc(text) -> str:
    """Escape anything that reaches rendered HTML.  User-entered message text
    always goes through here."""
    return html.escape(str(text), quote=True)


def badge(text: str) -> str:
    key = str(text).upper().split()[0] if text else ""
    fg, bg = STATUS_COLOURS.get(str(text).upper(), STATUS_COLOURS.get(key, (INK, "#e5e9f2")))
    return f'<span class="qkd-badge" style="color:{fg};background:{bg}">{esc(text)}</span>'


def card(label: str, value: str, unit: str = "", sub: str = "",
         badge_text: str | None = None, small: bool = False) -> None:
    bits = [f'<div class="qkd-card"><div class="label">{esc(label)}']
    if badge_text:
        bits.append(f' &nbsp;{badge(badge_text)}')
    bits.append("</div>")
    cls = "value small" if small else "value"
    bits.append(f'<div class="{cls}">{esc(value)}'
                + (f'<span class="unit">{esc(unit)}</span>' if unit else "")
                + "</div>")
    if sub:
        bits.append(f'<div class="sub">{esc(sub)}</div>')
    bits.append("</div>")
    st.markdown("".join(bits), unsafe_allow_html=True)


def note(text: str, warn: bool = False) -> None:
    cls = "qkd-warn" if warn else "qkd-note"
    st.markdown(f'<div class="{cls}">{esc(text)}</div>', unsafe_allow_html=True)


def stage_card(index: int, title: str, state: str, detail: str) -> None:
    st.markdown(
        f'<div class="qkd-stage"><div class="n">Stage {index:02d}</div>'
        f'<div class="t">{esc(title)}</div>{badge(state)}'
        f'<div style="color:{MUTED};margin-top:6px">{esc(detail)}</div></div>',
        unsafe_allow_html=True)
