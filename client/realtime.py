from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Callable
from typing import Any


RealtimeEventHandler = Callable[[dict[str, Any]], None]
RealtimeErrorHandler = Callable[[str], None]


def parse_realtime_event(text: str) -> dict[str, Any] | None:
    try:
        event = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(event, dict) or not isinstance(event.get("type"), str):
        return None
    return event


def websocket_url(base_url: str, token: str) -> str:
    base = base_url.rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://") :]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://") :]
    return f"{base}/ws/{token}"


class RealtimeClient:
    """Background WebSocket listener for GUI use."""

    def __init__(
        self,
        base_url: str,
        token: str,
        on_event: RealtimeEventHandler,
        on_error: RealtimeErrorHandler | None = None,
    ):
        self.base_url = base_url
        self.token = token
        self.on_event = on_event
        self.on_error = on_error
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="secure-chat-realtime", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def _run(self) -> None:
        asyncio.run(self._listen())

    async def _listen(self) -> None:
        try:
            import websockets
        except ModuleNotFoundError:
            if self.on_error:
                self.on_error("Missing realtime dependency. Install requirements again.")
            return

        url = websocket_url(self.base_url, self.token)
        while not self._stop_event.is_set():
            try:
                async with websockets.connect(url) as websocket:
                    while not self._stop_event.is_set():
                        text = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                        event = parse_realtime_event(text)
                        if event:
                            self.on_event(event)
            except asyncio.TimeoutError:
                continue
            except Exception as exc:  # pragma: no cover - network timing differs across GUI runs.
                if self.on_error:
                    self.on_error(f"Realtime connection interrupted: {exc}")
                await asyncio.sleep(1.5)
