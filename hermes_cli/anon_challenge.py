"""Nous free tier: the browser challenge the account service may put in front of a token exchange.

NAS can answer ``POST /api/anonymous/token`` with **428** ``challenge_required`` and a list of
challenges. Hermes implements exactly one primitive, ``browser-v1``: *open this portal URL, poll
until it clears, exchange again*. Everything the page does (bot detection, an in-browser proof of
work, an interactive fallback, its copy) belongs to the portal and changes without a Hermes release.

Who opens the URL depends on the surface:

* **desktop** (``HERMES_DESKTOP=1``): this process never opens anything. It publishes the challenge
  (``free_tier.challenge`` global event, and ``free_tier.status``'s ``challenge`` field for a client
  that connects later); the renderer hands it to the Electron main process, which loads it in a
  HIDDEN window and reveals that window only if the page asks for the human.
* **terminal**: print the URL, and open the system browser when there is a graphical one to open.

The wait runs OUTSIDE the auth-store and shared-store locks: the exchange that hit the 428 has
already unwound (the exception left the ``with`` blocks), so a slow page never stalls a sibling
profile or process. One challenge is worked at a time per process; a second thread that hits the
same 428 waits for the first and then simply exchanges again (NAS hands a retried mint the same
ticket, and a cleared credential a token).

An *optional* challenge (``required: false`` on a successful exchange: the service is measuring, not
enforcing) is only ever announced to a desktop client, never opened in a user's browser, and
nothing waits on it.
"""

from __future__ import annotations

import logging
import os
import platform
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, TypeVar
from urllib.parse import urlparse

from hermes_cli.auth_constants import AuthError, httpx

logger = logging.getLogger("hermes_cli.auth")

BROWSER_CAPABILITY = "browser-v1"
CHALLENGE_EVENT = "free_tier.challenge"
ANON_CHALLENGE_REQUIRED = "anon_challenge_required"
ANON_SIGNIN_REQUIRED = "anon_signin_required"

# How long one exchange attempt waits for its challenge. The page normally clears in seconds; this
# bounds the interactive case (a human solving a check) without parking a request for the ticket's
# whole ten minutes. A later attempt resumes the same ticket.
CHALLENGE_WAIT_SECONDS = 120.0
_POLL_MIN_SECONDS, _POLL_MAX_SECONDS = 1.0, 5.0
_MESSAGE_MAX_CHARS = 300

CHALLENGE_COPY = "Nous needs to run a quick check before starting your free session."
CHALLENGE_PENDING_COPY = "Finish the quick check in your browser, then try again."
SIGNIN_REQUIRED_COPY = "Free guest access isn't available here. Sign in with a Nous account to continue."

T = TypeVar("T")


@dataclass(frozen=True)
class BrowserChallenge:
    url: str
    required: bool
    expires_in: float
    interval: float
    message: str

    def as_payload(self) -> Dict[str, Any]:
        return {"type": "browser", "url": self.url, "required": self.required,
                "expires_in": int(self.expires_in), "message": self.message}


class AnonChallengeRequired(AuthError):
    """The exchange needs a browser challenge first. Carries what :func:`run_with_challenge` needs
    to work it: the challenge, and the portal + credential to poll with (set by the exchange)."""

    def __init__(self, challenge: BrowserChallenge) -> None:
        super().__init__(challenge.message, provider="nous", code=ANON_CHALLENGE_REQUIRED, retryable=True)
        self.challenge = challenge
        self.portal_base_url = ""
        self.anon_token = ""


def signin_required_error(message: Any = None) -> AuthError:
    """The service will not serve this client without an account (or asked for something this
    version cannot do). Terminal for the process, like a closed gate."""
    return AuthError(server_message(message) or SIGNIN_REQUIRED_COPY, provider="nous",
                     code=ANON_SIGNIN_REQUIRED, retryable=False)


def server_message(value: Any) -> str:
    """User-facing copy the service sent, if it is plausibly that: a short single paragraph."""
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    return text if 0 < len(text) <= _MESSAGE_MAX_CHARS else ""


# --- What this client tells the service about itself -------------------------------------------------


def client_surface() -> str:
    return "desktop" if (os.environ.get("HERMES_DESKTOP") or "").strip() == "1" else "cli"


def client_info() -> Dict[str, Any]:
    """The self-reported ``client`` block on a token exchange. It sorts honest clients (which
    surface, which challenge primitives) for the service's rules; it proves nothing, by design."""
    from hermes_cli import __version__
    return {"name": "hermes-agent", "version": __version__, "surface": client_surface(),
            "platform": sys.platform, "capabilities": [BROWSER_CAPABILITY]}


def user_agent() -> str:
    from hermes_cli import __version__
    return f"hermes-agent/{__version__} ({client_surface()}; {sys.platform}; {platform.machine() or 'unknown'})"


# --- Parsing ------------------------------------------------------------------------------------------


def _same_origin(url: str, portal_base_url: str) -> bool:
    """A challenge URL is only ever opened on the portal the exchange itself went to: the response
    is network input, and "open this URL" must not become "open any URL"."""
    try:
        target, portal = urlparse(url), urlparse(portal_base_url)
    except ValueError:
        return False
    return (target.scheme in ("https", "http") and target.scheme == portal.scheme
            and bool(target.netloc) and target.netloc.lower() == portal.netloc.lower())


def _number(value: Any, default: float) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else default


def parse_browser_challenge(payload: Dict[str, Any], portal_base_url: str) -> Optional[BrowserChallenge]:
    """The first challenge in ``payload["challenges"]`` this client can run, or None."""
    entries = payload.get("challenges")
    if not isinstance(entries, list):
        return None
    message = server_message(payload.get("message")) or CHALLENGE_COPY
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "browser":
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not _same_origin(url, portal_base_url):
            logger.info("Nous free tier: ignoring a challenge URL outside the portal origin")
            continue
        return BrowserChallenge(
            url=url, required=entry.get("required") is not False,
            expires_in=max(0.0, _number(entry.get("expires_in"), 600.0)),
            interval=min(_POLL_MAX_SECONDS, max(_POLL_MIN_SECONDS, _number(entry.get("interval"), 2.0))),
            message=message)
    return None


def challenge_error(payload: Dict[str, Any], portal_base_url: str) -> AuthError:
    """The error for a 428 ``challenge_required``: a challenge to work, or (nothing offered that
    this version can run) the sign-in fallback."""
    challenge = parse_browser_challenge(payload, portal_base_url)
    # The payload's ``message`` describes the challenge, so it is not reused for the fallback.
    return AnonChallengeRequired(challenge) if challenge else signin_required_error()


# --- Pending challenge: what a status read shows --------------------------------------------------------

_pending_lock = threading.Lock()
_pending: Dict[str, Dict[str, Any]] = {}
_work_lock = threading.Lock()    # one challenge worked at a time per process


def _profile_key() -> str:
    from hermes_cli.anon_auth import _mint_memo_key
    return _mint_memo_key()


def pending_challenge() -> Optional[Dict[str, Any]]:
    """The challenge this profile is waiting on, for ``free_tier.status`` (a client that connected
    after the event fired still learns it has a window to open). None once cleared or expired."""
    with _pending_lock:
        entry = _pending.get(_profile_key())
        if entry and entry["deadline"] <= time.monotonic():
            _pending.pop(_profile_key(), None)
            entry = None
        return dict(entry["payload"]) if entry else None


def _set_pending(challenge: Optional[BrowserChallenge]) -> None:
    with _pending_lock:
        if challenge is None:
            _pending.pop(_profile_key(), None)
        else:
            _pending[_profile_key()] = {"payload": challenge.as_payload(),
                                        "deadline": time.monotonic() + challenge.expires_in}


def reset_for_tests() -> None:
    with _pending_lock:
        _pending.clear()
    _gave_up_until.clear()


# --- Presenting ---------------------------------------------------------------------------------------


def _announce(challenge: BrowserChallenge) -> None:
    try:
        from tui_gateway.server import _broadcast_global_event
        _broadcast_global_event(CHALLENGE_EVENT, challenge.as_payload())
    except Exception as exc:  # no serve process: nobody to tell
        logger.debug("%s not broadcast: %s", CHALLENGE_EVENT, exc)


def _present_in_terminal(challenge: BrowserChallenge) -> None:
    from hermes_cli.auth_device_flow import _can_open_graphical_browser, _is_remote_session
    opened = False
    if not _is_remote_session() and _can_open_graphical_browser():
        try:
            import webbrowser
            opened = bool(webbrowser.open(challenge.url))
        except Exception as exc:
            logger.debug("could not open the challenge in a browser: %s", exc)
    print(f"\n{challenge.message}", file=sys.stderr)
    print(f"  Open: {challenge.url}", file=sys.stderr)
    print("  (Opened in your browser.)\n" if opened
          else "  (Open that link in any browser; this continues on its own.)\n", file=sys.stderr)


def present(challenge: BrowserChallenge) -> None:
    """Get the URL in front of something that can load it. Seam for tests (``_presenter``)."""
    if client_surface() == "desktop":
        _announce(challenge)
    elif challenge.required:
        _present_in_terminal(challenge)


_presenter: Callable[[BrowserChallenge], None] = present
_sleep = time.sleep     # seam for tests


# --- Working a challenge ----------------------------------------------------------------------------


def _poll_status(client: httpx.Client, portal_base_url: str, anon_token: str) -> str:
    """One status read. Anything that is not a clear ``pending`` / ``needs_interaction`` ends the
    wait: the exchange that follows is the authority on whether the credential is cleared. (A
    passed challenge reads ``none``: passing detaches the ticket.)"""
    from hermes_cli.anon_auth import _anon_headers
    try:
        response = client.post(f"{portal_base_url.rstrip('/')}/api/anonymous/challenge/status",
                               headers=_anon_headers(), json={"token": anon_token})
        body = response.json() if response.status_code == 200 else {}
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("challenge status poll failed: %s", exc)
        return "pending"   # a blip is not a verdict; the deadline bounds the wait
    status = body.get("status") if isinstance(body, dict) else None
    return status if isinstance(status, str) else "none"


_WAITING = ("pending", "needs_interaction")
# After one attempt ran out of patience, the callers queued behind it fail fast for this long
# instead of each parking for another full wait (boot fires a burst of token reads).
_GAVE_UP_COOLDOWN_SECONDS = 30.0
_gave_up_until: Dict[str, float] = {}


def wait_for_challenge(exc: AnonChallengeRequired, *, timeout_seconds: Optional[float] = None) -> bool:
    """Present *exc*'s challenge and poll until it leaves the waiting states. True = settled (go
    exchange again); False = still waiting when this attempt's patience ran out.

    Called under ``_work_lock``. A caller that queued behind another finds the ticket already
    settled on its first status read and returns without presenting anything."""
    from hermes_cli.auth import _resolve_verify
    from hermes_cli.auth_nous import _nous_http_client
    key = _profile_key()
    if time.monotonic() < _gave_up_until.get(key, 0.0):
        return False
    challenge = exc.challenge
    patience = CHALLENGE_WAIT_SECONDS if timeout_seconds is None else timeout_seconds
    deadline = time.monotonic() + min(patience, challenge.expires_in or patience)
    verify = _resolve_verify(insecure=None, ca_bundle=None, auth_state=None)
    told_interactive = False
    try:
        with _nous_http_client(10.0, verify) as client:
            if _poll_status(client, exc.portal_base_url, exc.anon_token) not in _WAITING:
                return True
            _set_pending(challenge)
            _presenter(challenge)
            while time.monotonic() < deadline:
                _sleep(challenge.interval)
                status = _poll_status(client, exc.portal_base_url, exc.anon_token)
                if status not in _WAITING:
                    return True
                if status == "needs_interaction" and not told_interactive:
                    told_interactive = True
                    if client_surface() != "desktop":
                        print("  Finish the quick check in your browser to continue.", file=sys.stderr)
        _gave_up_until[key] = time.monotonic() + _GAVE_UP_COOLDOWN_SECONDS
        return False
    finally:
        _set_pending(None)


def _still_pending(cause: AnonChallengeRequired) -> AuthError:
    error = AuthError(CHALLENGE_PENDING_COPY, provider="nous", code=ANON_CHALLENGE_REQUIRED, retryable=True)
    error.__cause__ = cause
    return error


def run_with_challenge(exchange: Callable[[], T]) -> T:
    """Run *exchange*; if the service asks for a browser challenge, work it (outside every lock:
    the exception has already unwound them) and run *exchange* once more.

    A second ``challenge_required`` is not looped on: it surfaces as a retryable error whose copy
    says what the user can do, and the next attempt resumes the same ticket."""
    try:
        return exchange()
    except AnonChallengeRequired as exc:
        first = exc
    with _work_lock:
        settled = wait_for_challenge(first)
    if not settled:
        raise _still_pending(first)
    try:
        return exchange()
    except AnonChallengeRequired as again:
        raise _still_pending(again) from None


def note_optional_challenges(payload: Dict[str, Any], portal_base_url: str) -> None:
    """A successful exchange may advertise a challenge nobody has to pass (the service is measuring
    before it enforces). Only a desktop client runs it, hidden; a terminal never opens a browser
    for something optional. Fire and forget."""
    if client_surface() != "desktop":
        return
    challenge = parse_browser_challenge(payload, portal_base_url)
    if challenge is not None and not challenge.required:
        _announce(challenge)
