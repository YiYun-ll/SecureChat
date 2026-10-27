from __future__ import annotations

import html
import sys
from pathlib import Path
from typing import Any

from client.api_client import SecureChatApiClient
from client.local_store import LocalChatStore
from client.realtime import RealtimeClient
from common.secure_chat import crypto_utils as crypto
from common.secure_chat import file_transfer, key_store, messages


APP_QSS = """
QWidget {
    background: #f6f2ec;
    color: #1f2937;
    font-family: "PingFang SC", "Microsoft YaHei", "Inter", sans-serif;
    font-size: 14px;
}
QLineEdit, QTextEdit {
    background: #fffaf3;
    border: 1px solid #e7dac8;
    border-radius: 10px;
    padding: 10px;
}
QTextBrowser {
    background: #fffaf3;
    border: 1px solid #eadfce;
    border-radius: 14px;
}
QPushButton {
    background: #ef7d3c;
    border: none;
    border-radius: 10px;
    color: white;
    font-weight: 700;
    padding: 10px 14px;
}
QPushButton:hover {
    background: #df6d2d;
}
QPushButton#secondaryButton {
    background: #ffffff;
    border: 1px solid #eadfce;
    color: #374151;
}
QPushButton#ghostButton {
    background: transparent;
    border: 1px solid #d8c9b8;
    color: #6b4e35;
}
QLabel#brand {
    font-size: 30px;
    font-weight: 900;
    color: #1f2937;
}
QLabel#subtitle {
    color: #7c6f64;
}
QFrame#authCard, QFrame#sidePanel, QFrame#securityPanel {
    background: #fffaf3;
    border: 1px solid #eadfce;
    border-radius: 18px;
}
QFrame#topBar {
    background: #fffaf3;
    border: 1px solid #eadfce;
    border-radius: 14px;
}
QListWidget {
    background: transparent;
    border: none;
    outline: none;
}
QListWidget::item {
    background: #ffffff;
    border: 1px solid #ede2d2;
    border-radius: 12px;
    margin: 4px;
    padding: 10px;
}
QListWidget::item:selected {
    background: #fee7d6;
    border-color: #ef7d3c;
    color: #1f2937;
}
"""


def _client_root(username: str) -> Path:
    return Path("client_data") / username


def _short_fingerprint(value: str) -> str:
    if not value:
        return "未获取"
    return value[:18] + "..." + value[-8:]


def _bubble(direction: str, text: str, status: str) -> str:
    safe_text = html.escape(text)
    safe_status = html.escape(status)
    if direction == "out":
        return (
            "<div style='margin:10px 8px;text-align:right;'>"
            "<span style='display:inline-block;max-width:68%;background:#ef7d3c;color:white;"
            "border-radius:16px 16px 4px 16px;padding:10px 13px;text-align:left;'>"
            f"{safe_text}<br><small style='opacity:.85'>{safe_status}</small></span></div>"
        )
    return (
        "<div style='margin:10px 8px;text-align:left;'>"
        "<span style='display:inline-block;max-width:68%;background:#ffffff;color:#1f2937;"
        "border:1px solid #eadfce;border-radius:16px 16px 16px 4px;padding:10px 13px;'>"
        f"{safe_text}<br><small style='color:#7c6f64'>{safe_status}</small></span></div>"
    )


def _load_qt():
    try:
        from PySide6.QtCore import QObject, Qt, Signal, Slot
        from PySide6.QtWidgets import (
            QApplication,
            QFileDialog,
            QFrame,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QListWidget,
            QListWidgetItem,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QSplitter,
            QStackedWidget,
            QTextBrowser,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except ModuleNotFoundError:
        return None
    return {
        "QApplication": QApplication,
        "QFileDialog": QFileDialog,
        "QFrame": QFrame,
        "QHBoxLayout": QHBoxLayout,
        "QLabel": QLabel,
        "QLineEdit": QLineEdit,
        "QListWidget": QListWidget,
        "QListWidgetItem": QListWidgetItem,
        "QMainWindow": QMainWindow,
        "QMessageBox": QMessageBox,
        "QObject": QObject,
        "QPushButton": QPushButton,
        "QSplitter": QSplitter,
        "QStackedWidget": QStackedWidget,
        "QTextBrowser": QTextBrowser,
        "QTextEdit": QTextEdit,
        "QVBoxLayout": QVBoxLayout,
        "QWidget": QWidget,
        "Qt": Qt,
        "Signal": Signal,
        "Slot": Slot,
    }


def build_app(qt: dict[str, Any]):
    QApplication = qt["QApplication"]
    QFileDialog = qt["QFileDialog"]
    QFrame = qt["QFrame"]
    QHBoxLayout = qt["QHBoxLayout"]
    QLabel = qt["QLabel"]
    QLineEdit = qt["QLineEdit"]
    QListWidget = qt["QListWidget"]
    QListWidgetItem = qt["QListWidgetItem"]
    QMainWindow = qt["QMainWindow"]
    QMessageBox = qt["QMessageBox"]
    QObject = qt["QObject"]
    QPushButton = qt["QPushButton"]
    QSplitter = qt["QSplitter"]
    QStackedWidget = qt["QStackedWidget"]
    QTextBrowser = qt["QTextBrowser"]
    QTextEdit = qt["QTextEdit"]
    QVBoxLayout = qt["QVBoxLayout"]
    QWidget = qt["QWidget"]
    Qt = qt["Qt"]
    Signal = qt["Signal"]
    Slot = qt["Slot"]

    class GuiSignals(QObject):
        realtime_event = Signal(object)
        realtime_error = Signal(str)

    class LoginPage(QWidget):
        authenticated = Signal(object, object, object, str)

        def __init__(self):
            super().__init__()
            page = QVBoxLayout(self)
            page.setAlignment(Qt.AlignCenter)
            card = QFrame()
            card.setObjectName("authCard")
            card.setFixedWidth(460)
            layout = QVBoxLayout(card)
            layout.setContentsMargins(30, 30, 30, 30)
            layout.setSpacing(14)

            brand = QLabel("Secure Chat")
            brand.setObjectName("brand")
            subtitle = QLabel("端到端加密聊天 · 实时密文中继 · 安全文件传输")
            subtitle.setObjectName("subtitle")
            self.base_url = QLineEdit("http://127.0.0.1:8000")
            self.username = QLineEdit()
            self.username.setPlaceholderText("用户名")
            self.password = QLineEdit()
            self.password.setPlaceholderText("本地密钥库/登录密码")
            self.password.setEchoMode(QLineEdit.Password)
            login = QPushButton("登录")
            register = QPushButton("注册并登录")
            register.setObjectName("secondaryButton")
            hint = QLabel("首次使用请选择注册；之后登录会解锁本地加密私钥。")
            hint.setObjectName("subtitle")

            login.clicked.connect(self.login)
            register.clicked.connect(self.register)
            for widget in [brand, subtitle, self.base_url, self.username, self.password, login, register, hint]:
                layout.addWidget(widget)
            page.addWidget(card)

        def _paths(self) -> tuple[str, str, Path]:
            username = self.username.text().strip()
            password = self.password.text()
            root = _client_root(username)
            return username, password, root / "key_store.json"

        def _client(self) -> SecureChatApiClient:
            return SecureChatApiClient(self.base_url.text().strip())

        @Slot()
        def register(self) -> None:
            username, password, key_path = self._paths()
            if not username or not password:
                QMessageBox.warning(self, "缺少信息", "请输入用户名和密码。")
                return
            try:
                store = key_store.create_key_store(username, password, key_path)
                api = self._client()
                api.register(store, password)
                api.login(store, password)
                local = LocalChatStore(_client_root(username) / "chat.sqlite")
                self.authenticated.emit(api, store, local, self.base_url.text().strip())
            except Exception as exc:
                QMessageBox.critical(self, "注册失败", str(exc))

        @Slot()
        def login(self) -> None:
            username, password, key_path = self._paths()
            if not key_path.exists():
                QMessageBox.warning(self, "没有本地密钥库", "请先注册，或确认用户名是否正确。")
                return
            try:
                store = key_store.unlock_key_store(key_path, password)
                api = self._client()
                api.login(store, password)
                local = LocalChatStore(_client_root(username) / "chat.sqlite")
                self.authenticated.emit(api, store, local, self.base_url.text().strip())
            except Exception as exc:
                QMessageBox.critical(self, "登录失败", str(exc))

    class ChatPage(QWidget):
        logged_out = Signal()

        def __init__(self):
            super().__init__()
            self.api: SecureChatApiClient | None = None
            self.store: key_store.UnlockedKeyStore | None = None
            self.local: LocalChatStore | None = None
            self.base_url = "http://127.0.0.1:8000"
            self.current_peer: str | None = None
            self.sessions: dict[str, messages.SecureSession] = {}
            self.replay_trackers: dict[str, messages.ReplayTracker] = {}
            self.realtime: RealtimeClient | None = None
            self.signals = GuiSignals()
            self.signals.realtime_event.connect(self.handle_realtime_event)
            self.signals.realtime_error.connect(self.show_status)
            self._build_ui()

        def _build_ui(self) -> None:
            root = QHBoxLayout(self)
            root.setContentsMargins(18, 18, 18, 18)
            splitter = QSplitter(Qt.Horizontal)

            left = QFrame()
            left.setObjectName("sidePanel")
            left_layout = QVBoxLayout(left)
            left_layout.setContentsMargins(16, 16, 16, 16)
            left_layout.setSpacing(10)
            self.profile_label = QLabel("未登录")
            self.profile_label.setStyleSheet("font-size:20px;font-weight:900;")
            self.connection_label = QLabel("实时连接：未启动")
            self.connection_label.setObjectName("subtitle")
            self.friend_input = QLineEdit()
            self.friend_input.setPlaceholderText("输入好友用户名")
            add_friend = QPushButton("添加/查询好友")
            add_friend.clicked.connect(self.add_friend)
            accept_friend = QPushButton("接受好友")
            accept_friend.setObjectName("secondaryButton")
            accept_friend.clicked.connect(self.accept_friend)
            refresh_offline = QPushButton("刷新离线消息")
            refresh_offline.setObjectName("ghostButton")
            refresh_offline.clicked.connect(self.refresh_offline)
            friends_label = QLabel("好友列表")
            friends_label.setObjectName("subtitle")
            self.friend_list = QListWidget()
            self.friend_list.currentItemChanged.connect(self.friend_selected)
            self.logout_button = QPushButton("退出登录")
            self.logout_button.setObjectName("ghostButton")
            self.logout_button.clicked.connect(self.logout)

            for widget in [
                self.profile_label,
                self.connection_label,
                self.friend_input,
                add_friend,
                accept_friend,
                refresh_offline,
                friends_label,
            ]:
                left_layout.addWidget(widget)
            left_layout.addWidget(self.friend_list, 1)
            left_layout.addWidget(self.logout_button, 0, Qt.AlignLeft | Qt.AlignBottom)

            center = QWidget()
            center_layout = QVBoxLayout(center)
            self.top_bar = QFrame()
            self.top_bar.setObjectName("topBar")
            top_layout = QHBoxLayout(self.top_bar)
            self.chat_title = QLabel("选择一个好友开始聊天")
            self.chat_title.setStyleSheet("font-size:22px;font-weight:900;")
            self.chat_status = QLabel("消息会在客户端加密和验签")
            self.chat_status.setObjectName("subtitle")
            top_layout.addWidget(self.chat_title)
            top_layout.addStretch()
            top_layout.addWidget(self.chat_status)
            self.transcript = QTextBrowser()
            self.composer = QTextEdit()
            self.composer.setPlaceholderText("输入消息，按发送前会自动 AES-GCM 加密并签名")
            self.composer.setFixedHeight(86)
            actions = QHBoxLayout()
            send = QPushButton("发送加密消息")
            send.clicked.connect(self.send_message)
            send_file = QPushButton("发送安全文件")
            send_file.setObjectName("secondaryButton")
            send_file.clicked.connect(self.send_file)
            download_file = QPushButton("下载选中文件")
            download_file.setObjectName("ghostButton")
            download_file.clicked.connect(self.download_latest_file)
            actions.addWidget(send)
            actions.addWidget(send_file)
            actions.addWidget(download_file)
            center_layout.addWidget(self.top_bar)
            center_layout.addWidget(self.transcript, 1)
            center_layout.addWidget(self.composer)
            center_layout.addLayout(actions)

            right = QFrame()
            right.setObjectName("securityPanel")
            right_layout = QVBoxLayout(right)
            heading = QLabel("安全详情")
            heading.setStyleSheet("font-size:20px;font-weight:900;")
            self.peer_label = QLabel("好友：未选择")
            self.trust_label = QLabel("信任状态：未确认")
            self.sign_fp = QLabel("签名指纹：未获取")
            self.enc_fp = QLabel("加密指纹：未获取")
            self.session_label = QLabel("会话：未建立")
            self.file_list = QListWidget()
            self.event_log = QTextBrowser()
            self.event_log.setFixedHeight(160)
            for widget in [
                heading,
                self.peer_label,
                self.trust_label,
                self.sign_fp,
                self.enc_fp,
                self.session_label,
                QLabel("文件记录"),
                self.file_list,
                QLabel("事件"),
                self.event_log,
            ]:
                right_layout.addWidget(widget)

            splitter.addWidget(left)
            splitter.addWidget(center)
            splitter.addWidget(right)
            splitter.setSizes([260, 620, 300])
            root.addWidget(splitter)

        def activate(
            self,
            api: SecureChatApiClient,
            store: key_store.UnlockedKeyStore,
            local: LocalChatStore,
            base_url: str,
        ) -> None:
            self.api = api
            self.store = store
            self.local = local
            self.base_url = base_url
            self.profile_label.setText(store.owner)
            self.reload_friends()
            self.start_realtime()
            self.refresh_offline()

        def start_realtime(self) -> None:
            if not self.api or not self.api.access_token:
                return
            if self.realtime:
                self.realtime.stop()
            self.realtime = RealtimeClient(
                self.base_url,
                self.api.access_token,
                lambda event: self.signals.realtime_event.emit(event),
                lambda text: self.signals.realtime_error.emit(text),
            )
            self.realtime.start()
            self.connection_label.setText("实时连接：已启动")

        def show_status(self, text: str) -> None:
            self.connection_label.setText(text)
            self.event_log.append(html.escape(text))

        def reload_friends(self) -> None:
            self.friend_list.clear()
            if not self.local:
                return
            for friend in self.local.list_friends():
                item = QListWidgetItem(friend["username"])
                item.setData(Qt.UserRole, friend)
                self.friend_list.addItem(item)

        @Slot()
        def add_friend(self) -> None:
            if not self.api or not self.local:
                return
            username = self.friend_input.text().strip()
            if not username:
                QMessageBox.warning(self, "缺少好友", "请输入好友用户名。")
                return
            try:
                keys = self.api.get_public_keys(username)
                self.local.upsert_friend(
                    username=username,
                    signing_public_key_pem=keys["signing_public_key_pem"],
                    encryption_public_key_pem=keys["encryption_public_key_pem"],
                    signing_fingerprint=keys["signing_fingerprint"],
                    encryption_fingerprint=keys["encryption_fingerprint"],
                    trust_status="trusted",
                )
                self.api.request_friend(username)
                self.reload_friends()
                self.show_status(f"已获取 {username} 的公钥并发送好友请求。")
            except Exception as exc:
                QMessageBox.critical(self, "添加失败", str(exc))

        @Slot()
        def accept_friend(self) -> None:
            if not self.api:
                return
            username = self.friend_input.text().strip() or self.current_peer
            if not username:
                QMessageBox.warning(self, "缺少好友", "请输入或选择好友。")
                return
            try:
                self.api.accept_friend(username)
                self.show_status(f"已接受 {username} 的好友关系。")
            except Exception as exc:
                QMessageBox.critical(self, "接受失败", str(exc))

        def friend_selected(self, current, _previous) -> None:
            if not current:
                return
            friend = current.data(Qt.UserRole)
            self.current_peer = friend["username"]
            self.chat_title.setText(friend["username"])
            self.peer_label.setText(f"好友：{friend['username']}")
            self.trust_label.setText(f"信任状态：{friend['trust_status']}")
            self.sign_fp.setText(f"签名指纹：{_short_fingerprint(friend['signing_fingerprint'])}")
            self.enc_fp.setText(f"加密指纹：{_short_fingerprint(friend['encryption_fingerprint'])}")
            self.render_messages()
            self.render_files()

        def render_messages(self) -> None:
            if not self.local or not self.current_peer:
                self.transcript.setHtml("")
                return
            rows = self.local.list_messages(self.current_peer)
            html_rows = [_bubble(row["direction"], row["plaintext"] or "[密文]", row["status"]) for row in rows]
            self.transcript.setHtml("<div style='font-family:PingFang SC, sans-serif;'>" + "".join(html_rows) + "</div>")

        def render_files(self) -> None:
            self.file_list.clear()
            if not self.local or not self.current_peer:
                return
            for record in self.local.list_files(self.current_peer):
                manifest = record["manifest"]
                label = f"{manifest.get('safe_filename', record['file_id'])} · {record['direction']} · {record['status']}"
                item = QListWidgetItem(label)
                item.setData(Qt.UserRole, record)
                self.file_list.addItem(item)

        def _refresh_friend_keys(self, username: str) -> dict[str, Any]:
            assert self.api is not None and self.local is not None
            keys = self.api.get_public_keys(username)
            self.local.upsert_friend(
                username=username,
                signing_public_key_pem=keys["signing_public_key_pem"],
                encryption_public_key_pem=keys["encryption_public_key_pem"],
                signing_fingerprint=keys["signing_fingerprint"],
                encryption_fingerprint=keys["encryption_fingerprint"],
                trust_status="trusted",
            )
            self.reload_friends()
            return self.local.get_friend(username)

        def _session_for_package(self, sender: str, package: dict[str, Any]) -> messages.SecureSession:
            assert self.store is not None and self.local is not None
            manifest = package.get("manifest", {})
            target_session_id = manifest.get("session_id")
            cached = self.sessions.get(sender)
            if cached and cached.session_id == target_session_id:
                return cached

            friend = self._save_friend_from_directory(sender)
            signing_public = crypto.load_public_key_pem(friend["signing_public_key_pem"])
            envelope = package.get("session_envelope")
            if not envelope or (target_session_id and envelope.get("session_id") != target_session_id):
                saved = self.local.get_session(sender)
                if saved and (not target_session_id or saved.get("session_id") == target_session_id):
                    envelope = saved
            if not envelope:
                raise file_transfer.FileTransferError("missing file session envelope")
            try:
                session = messages.accept_session(
                    envelope,
                    signing_public,
                    self.store.encryption_private_key,
                )
            except messages.MessageSecurityError as exc:
                if "unwrap" in str(exc):
                    raise file_transfer.FileTransferError(
                        "会话密钥解封失败：发送方可能使用了过期的你的公钥。"
                        "请让对方重新点击「添加/查询好友」刷新公钥后重发文件。"
                    ) from exc
                raise file_transfer.FileTransferError(str(exc)) from exc
            self.sessions[sender] = session
            self.local.save_session(sender, envelope)
            return session

        def _selected_friend(self) -> dict[str, Any] | None:
            if not self.local or not self.current_peer:
                return None
            return self.local.get_friend(self.current_peer)

        def _ensure_outgoing_session(self, friend: dict[str, Any]) -> messages.SecureSession:
            assert self.store is not None and self.local is not None
            peer = friend["username"]
            session = self.sessions.get(peer)
            if session:
                return session
            friend = self._refresh_friend_keys(peer)
            session = messages.create_session(
                self.store.owner,
                peer,
                self.store.signing_private_key,
                crypto.load_public_key_pem(friend["encryption_public_key_pem"]),
            )
            self.sessions[peer] = session
            self.local.save_session(peer, session.envelope)
            self.session_label.setText(f"会话：{session.session_id[:8]} 已建立")
            return session

        @Slot()
        def send_message(self) -> None:
            if not self.api or not self.store or not self.local:
                return
            friend = self._selected_friend()
            if not friend:
                QMessageBox.warning(self, "没有好友", "请先选择好友。")
                return
            plaintext = self.composer.toPlainText().strip()
            if not plaintext:
                return
            try:
                session = self._ensure_outgoing_session(friend)
                packet = messages.encrypt_text_message(session, self.store.signing_private_key, plaintext)
                relay_payload = {"kind": "text", "session_envelope": session.envelope, "message": packet}
                self.api.store_offline_message(friend["username"], relay_payload)
                self.local.save_message(
                    peer=friend["username"],
                    direction="out",
                    packet=relay_payload,
                    plaintext=plaintext,
                    status="sent · encrypted · signed",
                )
                self.composer.clear()
                self.render_messages()
            except Exception as exc:
                QMessageBox.critical(self, "发送失败", str(exc))

        @Slot()
        def send_file(self) -> None:
            if not self.api or not self.store or not self.local:
                return
            friend = self._selected_friend()
            if not friend:
                QMessageBox.warning(self, "没有好友", "请先选择好友。")
                return
            path, _ = QFileDialog.getOpenFileName(self, "选择要安全发送的文件")
            if not path:
                return
            try:
                session = self._ensure_outgoing_session(friend)
                package = file_transfer.encrypt_file_for_session(path, session, self.store.signing_private_key)
                package["session_envelope"] = session.envelope
                response = self.api.upload_file_package(friend["username"], package)
                manifest = package["manifest"]
                self.local.save_file_record(
                    file_id=response["file_id"],
                    peer=friend["username"],
                    direction="out",
                    manifest=manifest,
                    local_path=path,
                    status="sent · scanned · encrypted",
                )
                self.local.save_message(
                    peer=friend["username"],
                    direction="out",
                    packet={"kind": "file", "file_id": response["file_id"]},
                    plaintext=f"已发送安全文件：{manifest['safe_filename']}",
                    status="file sent",
                )
                self.render_files()
                self.render_messages()
            except Exception as exc:
                QMessageBox.critical(self, "文件发送失败", str(exc))

        def _save_friend_from_directory(self, username: str) -> dict[str, Any]:
            assert self.api is not None and self.local is not None
            friend = self.local.get_friend(username)
            if friend:
                return friend
            keys = self.api.get_public_keys(username)
            self.local.upsert_friend(
                username=username,
                signing_public_key_pem=keys["signing_public_key_pem"],
                encryption_public_key_pem=keys["encryption_public_key_pem"],
                signing_fingerprint=keys["signing_fingerprint"],
                encryption_fingerprint=keys["encryption_fingerprint"],
                trust_status="trusted",
            )
            self.reload_friends()
            return self.local.get_friend(username)

        def _decrypt_incoming_text(self, sender: str, payload: dict[str, Any]) -> str:
            assert self.store is not None and self.local is not None
            friend = self._save_friend_from_directory(sender)
            packet = payload["message"] if payload.get("kind") == "text" else payload
            envelope = payload.get("session_envelope")
            session = self.sessions.get(sender)
            if envelope and (not session or session.session_id != envelope.get("session_id")):
                session = messages.accept_session(
                    envelope,
                    crypto.load_public_key_pem(friend["signing_public_key_pem"]),
                    self.store.encryption_private_key,
                )
                self.sessions[sender] = session
                self.local.save_session(sender, envelope)
            if not session:
                saved = self.local.get_session(sender)
                if saved:
                    session = messages.accept_session(
                        saved,
                        crypto.load_public_key_pem(friend["signing_public_key_pem"]),
                        self.store.encryption_private_key,
                    )
                    self.sessions[sender] = session
            if not session:
                raise messages.MessageSecurityError("missing session envelope")
            tracker = self.replay_trackers.setdefault(sender, messages.ReplayTracker())
            return messages.decrypt_text_message(
                packet,
                session,
                crypto.load_public_key_pem(friend["signing_public_key_pem"]),
                tracker,
            )

        def _handle_incoming_payload(self, sender: str, payload: dict[str, Any]) -> None:
            assert self.local is not None
            if payload.get("kind") == "text" or "ciphertext_b64" in payload:
                plaintext = self._decrypt_incoming_text(sender, payload)
                self.local.save_message(
                    peer=sender,
                    direction="in",
                    packet=payload,
                    plaintext=plaintext,
                    status="verified · decrypted",
                )
                if self.current_peer == sender:
                    self.render_messages()
                self.show_status(f"收到 {sender} 的实时加密消息，验签通过。")
            else:
                self.local.save_message(
                    peer=sender,
                    direction="in",
                    packet=payload,
                    plaintext="收到一条暂不识别的密文事件",
                    status="stored",
                )

        @Slot()
        def refresh_offline(self) -> None:
            if not self.api:
                return
            try:
                response = self.api.fetch_offline_messages()
                for item in response.get("messages", []):
                    self._handle_incoming_payload(item["sender"], item["packet"])
                self.show_status(f"离线消息刷新完成：{len(response.get('messages', []))} 条。")
            except Exception as exc:
                self.show_status(f"离线刷新失败：{exc}")

        @Slot(object)
        def handle_realtime_event(self, event: dict[str, Any]) -> None:
            if not self.local:
                return
            try:
                if event.get("type") == "message":
                    self._handle_incoming_payload(event["sender"], event["packet"])
                elif event.get("type") == "file":
                    sender = event["sender"]
                    manifest = event["manifest"]
                    self._save_friend_from_directory(sender)
                    self.local.save_file_record(
                        file_id=event["file_id"],
                        peer=sender,
                        direction="in",
                        manifest=manifest,
                        local_path=None,
                        status="available · encrypted",
                    )
                    self.local.save_message(
                        peer=sender,
                        direction="in",
                        packet={"kind": "file", "file_id": event["file_id"]},
                        plaintext=f"收到安全文件：{manifest.get('safe_filename', event['file_id'])}",
                        status="file available",
                    )
                    if self.current_peer == sender:
                        self.render_files()
                        self.render_messages()
                    self.show_status(f"收到 {sender} 的加密文件包。")
            except Exception as exc:
                self.show_status(f"实时事件处理失败：{exc}")

        @Slot()
        def download_latest_file(self) -> None:
            if not self.api or not self.store or not self.local:
                return
            item = self.file_list.currentItem()
            if not item:
                QMessageBox.information(self, "未选择文件", "请先在右侧文件记录中选择一个文件。")
                return
            record = item.data(Qt.UserRole)
            if record["direction"] != "in":
                QMessageBox.information(self, "无需下载", "本地发送文件已经在原路径。")
                return
            try:
                response = self.api.download_file_package(record["file_id"])
                sender = response["sender"]
                friend = self._save_friend_from_directory(sender)
                package = response["package"]
                session = self._session_for_package(sender, package)
                download_dir = _client_root(self.store.owner) / "downloads"
                download_dir.mkdir(parents=True, exist_ok=True)
                output_path = download_dir / package["manifest"]["safe_filename"]
                file_transfer.decrypt_file_from_package(
                    package,
                    session,
                    crypto.load_public_key_pem(friend["signing_public_key_pem"]),
                    output_path,
                )
                self.local.save_file_record(
                    file_id=record["file_id"],
                    peer=sender,
                    direction="in",
                    manifest=package["manifest"],
                    local_path=str(output_path),
                    status="downloaded · verified · rescanned",
                )
                self.render_files()
                QMessageBox.information(self, "下载完成", f"文件已验证并保存到：{output_path}")
            except Exception as exc:
                QMessageBox.critical(self, "下载失败", str(exc))

        def shutdown(self) -> None:
            if self.realtime:
                self.realtime.stop()
                self.realtime = None
            if self.local:
                self.local.close()
                self.local = None
            if self.api and hasattr(self.api._client, "close"):
                self.api._client.close()
            if self.api:
                self.api.access_token = None
                self.api = None
            self.store = None

        def _reset_ui(self) -> None:
            self.current_peer = None
            self.sessions.clear()
            self.replay_trackers.clear()
            self.profile_label.setText("未登录")
            self.connection_label.setText("实时连接：未启动")
            self.friend_input.clear()
            self.friend_list.clear()
            self.chat_title.setText("选择一个好友开始聊天")
            self.chat_status.setText("消息会在客户端加密和验签")
            self.transcript.clear()
            self.composer.clear()
            self.peer_label.setText("好友：未选择")
            self.trust_label.setText("信任状态：未确认")
            self.sign_fp.setText("签名指纹：未获取")
            self.enc_fp.setText("加密指纹：未获取")
            self.session_label.setText("会话：未建立")
            self.file_list.clear()
            self.event_log.clear()

        @Slot()
        def logout(self) -> None:
            username = self.store.owner if self.store else "当前用户"
            answer = QMessageBox.question(
                self,
                "退出登录",
                f"确定退出 {username} 吗？退出后将返回登录界面，本地聊天记录仍会保留。",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.shutdown()
            self._reset_ui()
            self.logged_out.emit()

    class SecureChatWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Secure Chat · 安全即时通讯")
            self.resize(1220, 760)
            self.stack = QStackedWidget()
            self.login_page = LoginPage()
            self.chat_page = ChatPage()
            self.login_page.authenticated.connect(self.open_chat)
            self.chat_page.logged_out.connect(self.return_to_login)
            self.stack.addWidget(self.login_page)
            self.stack.addWidget(self.chat_page)
            self.setCentralWidget(self.stack)

        @Slot(object, object, object, str)
        def open_chat(
            self,
            api: SecureChatApiClient,
            store: key_store.UnlockedKeyStore,
            local: LocalChatStore,
            base_url: str,
        ) -> None:
            self.chat_page.activate(api, store, local, base_url)
            self.stack.setCurrentWidget(self.chat_page)

        @Slot()
        def return_to_login(self) -> None:
            self.login_page.password.clear()
            self.stack.setCurrentWidget(self.login_page)

        def closeEvent(self, event) -> None:
            self.chat_page.shutdown()
            event.accept()

    return QApplication, SecureChatWindow


def main() -> int:
    qt = _load_qt()
    if qt is None:
        print("PySide6 is not installed. Run `python3 -m client.demo` for the CLI demo, or install PySide6.")
        return 0
    QApplication, SecureChatWindow = build_app(qt)
    app = QApplication(sys.argv)
    app.setStyleSheet(APP_QSS)
    window = SecureChatWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
