import base64
import hashlib
import json
from pathlib import Path

from pynicotine.config import config
from pynicotine.events import events
from pynicotine.pluginsystem import BasePlugin, returncode

try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Gdk", "4.0")
    from gi.repository import Gtk, GLib, Gdk
except Exception:
    Gtk = None
    GLib = None
    Gdk = None


class Plugin(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.settings = {
            "master_key": "change-this-key",
            "show_password_in_details": False,
            "capture_on_load": True,
            "capture_on_connect": True,
            "capture_on_shutdown": True,
            "update_existing_passwords": True,
            "poll_login_changes": True,
            "poll_interval_seconds": 60,
        }

        self.metasettings = {
            "master_key": {
                "description": "Master Key / Obfuscation Passphrase - stored in plaintext plugin settings",
                "type": "string",
            },
            "show_password_in_details": {
                "description": "Show decrypted password in popup by default",
                "type": "bool",
            },
            "capture_on_load": {
                "description": "Auto-capture current Nicotine+ login on plugin load",
                "type": "bool",
            },
            "capture_on_connect": {
                "description": "Auto-capture current Nicotine+ login after server connect",
                "type": "bool",
            },
            "capture_on_shutdown": {
                "description": "Auto-capture current Nicotine+ login on shutdown/plugin unload",
                "type": "bool",
            },
            "update_existing_passwords": {
                "description": "Update saved password if same username uses a new password",
                "type": "bool",
            },
            "poll_login_changes": {
                "description": "Silently poll Nicotine+ login/password for changes",
                "type": "bool",
            },
            "poll_interval_seconds": {
                "description": "Polling Interval Seconds",
                "type": "int",
                "minimum": 60,
                "maximum": 6000,
            },
        }

        self.commands = {
            "lockbox": {
                "callback": self.cmd_lockbox,
                "description": "Sync current login and open lockbox popup.",
            },
            "lockboxsync": {
                "callback": self.cmd_lockboxsync,
                "description": "Sync current Nicotine+ login without opening popup.",
            },
        }

        self._popup_window = None
        self._entries = []
        self._poll_token = None
        self._last_seen_login = None
        self._last_seen_passw = None

        self.data_dir = Path(config.data_folder_path) / "plugins" / self.internal_name
        self.json_path = self.data_dir / "lockbox.json"

    def init(self):
        self._entries = self._load_json_entries()

        if self.settings.get("capture_on_load", True):
            self._capture_current_login(source="LOAD", quiet=False)

        self.log("Lockbox loaded. Use /lockbox or /lockboxsync")

    def loaded_notification(self):
        if self.settings.get("capture_on_load", True):
            self._capture_current_login(source="LOADED_NOTIFICATION", quiet=False)

    def server_connect_notification(self, *_args, **_kwargs):
        if self.settings.get("capture_on_connect", True):
            self._capture_current_login(source="CONNECT", quiet=False)

        self._start_polling()

    def server_disconnect_notification(self, *_args, **_kwargs):
        self._stop_polling()

    def shutdown_notification(self, *_args, **_kwargs):
        if self.settings.get("capture_on_shutdown", True):
            self._capture_current_login(source="SHUTDOWN", quiet=False)

        self._stop_polling()

    def disable(self):
        if self.settings.get("capture_on_shutdown", True):
            self._capture_current_login(source="DISABLE", quiet=False)

        self._stop_polling()

        if self._popup_window is not None:
            try:
                self._popup_window.close()
            except Exception:
                pass

        self._popup_window = None

    def cmd_lockboxsync(self, _args=None, **_kwargs):
        self._entries = self._load_json_entries()
        changed = self._capture_current_login(source="MANUAL_SYNC", quiet=False)

        if changed:
            self.log("Manual lockbox sync complete: credentials saved/updated.")
        else:
            self.log("Manual lockbox sync complete: no credential changes.")

        return returncode["zap"]

    def cmd_lockbox(self, _args=None, **_kwargs):
        if Gtk is None or GLib is None:
            self.log("GTK unavailable. Cannot open lockbox popup.")
            return returncode["zap"]

        self._entries = self._load_json_entries()
        self._capture_current_login(source="LOCKBOX_OPEN", quiet=False)

        GLib.idle_add(self._show_lockbox_popup)
        return returncode["zap"]

    def _start_polling(self):
        self._stop_polling()

        if not self.settings.get("poll_login_changes", True):
            return

        self._poll_token = events.schedule(
            delay=self._poll_interval(),
            callback=self._poll_current_login,
        )

    def _stop_polling(self):
        if self._poll_token is None:
            return

        try:
            events.cancel_scheduled(self._poll_token)
        except Exception:
            pass

        self._poll_token = None

    def _poll_interval(self):
        value = int(self.settings.get("poll_interval_seconds", 60) or 60)
        return max(60, min(6000, value))

    def _poll_current_login(self):
        self._poll_token = None

        if not self.settings.get("poll_login_changes", True):
            return

        username = str(config.sections["server"].get("login", "") or "").strip()
        password = str(config.sections["server"].get("passw", "") or "")

        if username != self._last_seen_login or password != self._last_seen_passw:
            self._last_seen_login = username
            self._last_seen_passw = password
            self._entries = self._load_json_entries()
            self._capture_current_login(source="POLL", quiet=True)

        self._poll_token = events.schedule(
            delay=self._poll_interval(),
            callback=self._poll_current_login,
        )

    def _capture_current_login(self, source="UNKNOWN", quiet=False):
        username = str(config.sections["server"].get("login", "") or "").strip()
        password = str(config.sections["server"].get("passw", "") or "")

        if not username:
            if not quiet:
                self.log(f"[LOCKBOX:{source}] No Nicotine+ username configured.")
            return False

        if not password:
            if not quiet:
                self.log(f"[LOCKBOX:{source}] Username '{username}' has no configured password.")
            return False

        if not self._entries:
            self._entries = self._load_json_entries()

        changed = self._upsert_entry(
            username=username,
            password_plain=password,
            notes=f"Auto-captured from Nicotine+ {source}",
        )

        if changed:
            self._save_json_entries(self._entries)
            if not quiet:
                self.log(f"[LOCKBOX:{source}] Saved/updated credentials for username: {username}")
        elif not quiet:
            self.log(f"[LOCKBOX:{source}] Credentials already current for username: {username}")

        return changed

    def _upsert_entry(self, username, password_plain, notes=""):
        new_password_enc = self._encrypt_text(password_plain)

        for entry in self._entries:
            if entry.get("username") != username:
                continue

            try:
                old_password_plain = self._decrypt_text(entry.get("password_enc", ""))
            except Exception:
                old_password_plain = ""

            if old_password_plain == password_plain:
                if notes and not entry.get("notes"):
                    entry["notes"] = notes
                    return True
                return False

            if not self.settings.get("update_existing_passwords", True):
                self.log(f"Password changed for {username}, but auto-update is disabled.")
                return False

            entry["password_enc"] = new_password_enc
            entry["notes"] = notes
            return True

        self._entries.append({
            "username": username,
            "password_enc": new_password_enc,
            "notes": notes,
        })

        return True

    def _key_bytes(self):
        key = str(self.settings.get("master_key", "") or "")

        if not key:
            key = "default-key"

        return hashlib.sha256(key.encode("utf-8")).digest()

    def _xor_bytes(self, data):
        key = self._key_bytes()
        return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))

    def _encrypt_text(self, text):
        raw = str(text or "").encode("utf-8")
        xored = self._xor_bytes(raw)
        return base64.urlsafe_b64encode(xored).decode("ascii")

    def _decrypt_text(self, text):
        raw = base64.urlsafe_b64decode(str(text or "").encode("ascii"))
        plain = self._xor_bytes(raw)
        return plain.decode("utf-8")

    def _save_json_entries(self, entries):
        self.data_dir.mkdir(parents=True, exist_ok=True)

        payload = {
            "version": 2,
            "entries": entries,
        }

        with self.json_path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2, ensure_ascii=False)

    def _load_json_entries(self):
        if not self.json_path.exists():
            return []

        try:
            with self.json_path.open("r", encoding="utf-8") as file:
                payload = json.load(file)

            entries = payload.get("entries", [])

            if not isinstance(entries, list):
                return []

            clean = []

            for row in entries:
                if not isinstance(row, dict):
                    continue

                username = str(row.get("username", "") or "")
                password_enc = str(row.get("password_enc", "") or "")
                notes = str(row.get("notes", "") or "")

                if username:
                    clean.append({
                        "username": username,
                        "password_enc": password_enc,
                        "notes": notes,
                    })

            return clean

        except Exception as error:
            self.log(f"Unable to load lockbox JSON: {type(error).__name__}: {error}")
            return []

    def _copy_to_clipboard(self, text, window=None):
        text = str(text or "")

        try:
            if Gdk is not None:
                display = Gdk.Display.get_default()
                if display is not None:
                    clipboard = display.get_clipboard()
                    clipboard.set(text)
                    return True
        except Exception:
            pass

        try:
            if window is not None:
                window.get_clipboard().set(text)
                return True
        except Exception as error:
            self.log(f"Clipboard copy failed: {type(error).__name__}: {error}")
            return False

        self.log("Clipboard copy failed: no usable clipboard backend.")
        return False

    def _show_lockbox_popup(self):
        if self._popup_window is not None:
            try:
                self._popup_window.close()
            except Exception:
                pass

            self._popup_window = None

        window = Gtk.Window()
        window.set_title("Username Lockbox")
        window.set_default_size(600, 320)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_margin_top(12)
        outer.set_margin_bottom(12)
        outer.set_margin_start(12)
        outer.set_margin_end(12)

        note = Gtk.Label(
            label=(
                "If you change your Nicotine+ password mid-session, "
                "run /lockbox or /lockboxsync to update the saved password."
            )
        )
        note.set_xalign(0)
        note.set_wrap(True)
        outer.append(note)

        combo = Gtk.ComboBoxText()
        outer.append(combo)

        username_entry = Gtk.Entry()
        username_entry.set_placeholder_text("Username")
        outer.append(username_entry)

        password_entry = Gtk.Entry()
        password_entry.set_placeholder_text("Password")
        password_entry.set_visibility(bool(self.settings.get("show_password_in_details", False)))
        outer.append(password_entry)

        notes_entry = Gtk.Entry()
        notes_entry.set_placeholder_text("Notes")
        outer.append(notes_entry)

        show_password_check = Gtk.CheckButton(label="Show password")
        show_password_check.set_active(bool(self.settings.get("show_password_in_details", False)))
        outer.append(show_password_check)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        save_button = Gtk.Button(label="Save / Update")
        remove_button = Gtk.Button(label="Remove Selected")
        copy_user_button = Gtk.Button(label="Copy Username")
        copy_pass_button = Gtk.Button(label="Copy Password")
        capture_button = Gtk.Button(label="Capture Current Login")
        reload_button = Gtk.Button(label="Reload JSON")
        close_button = Gtk.Button(label="Close")

        buttons.append(save_button)
        buttons.append(remove_button)
        buttons.append(copy_user_button)
        buttons.append(copy_pass_button)
        buttons.append(capture_button)
        buttons.append(reload_button)
        buttons.append(close_button)

        outer.append(buttons)

        def decrypted_password_for(row):
            try:
                return self._decrypt_text(row.get("password_enc", ""))
            except Exception as error:
                self.log(f"Unable to decrypt password: {type(error).__name__}: {error}")
                return ""

        def get_selected_index():
            index = combo.get_active()

            if index < 0 or index >= len(self._entries):
                return -1

            return index

        def get_selected_row():
            index = get_selected_index()

            if index < 0:
                return None

            return self._entries[index]

        def rebuild_combo(select_username=None):
            combo.remove_all()

            selected_index = 0

            for index, row in enumerate(self._entries):
                username = row.get("username", "")
                combo.append_text(username)

                if select_username and username == select_username:
                    selected_index = index

            if self._entries:
                combo.set_active(selected_index)
            else:
                username_entry.set_text("")
                password_entry.set_text("")
                notes_entry.set_text("")

        def populate_fields_from_selected():
            row = get_selected_row()

            if row is None:
                return

            username_entry.set_text(row.get("username", ""))
            password_entry.set_text(decrypted_password_for(row))
            notes_entry.set_text(row.get("notes", ""))

        def save_or_update(_button):
            username = username_entry.get_text().strip()
            password_plain = password_entry.get_text()
            notes = notes_entry.get_text().strip()

            if not username:
                self.log("Cannot save lockbox entry: username is blank.")
                return

            found = False

            for entry in self._entries:
                if entry.get("username") == username:
                    entry["password_enc"] = self._encrypt_text(password_plain)
                    entry["notes"] = notes
                    found = True
                    break

            if not found:
                self._entries.append({
                    "username": username,
                    "password_enc": self._encrypt_text(password_plain),
                    "notes": notes,
                })

            self._save_json_entries(self._entries)
            rebuild_combo(select_username=username)
            self.log(f"Saved lockbox entry for username: {username}")

        def remove_selected(_button):
            index = get_selected_index()

            if index < 0:
                self.log("No lockbox entry selected to remove.")
                return

            username = self._entries[index].get("username", "")
            del self._entries[index]

            self._save_json_entries(self._entries)
            rebuild_combo()
            self.log(f"Removed lockbox entry for username: {username}")

        def copy_username(_button):
            row = get_selected_row()

            if row is None:
                return

            if self._copy_to_clipboard(row.get("username", ""), window=window):
                self.log("Copied username.")

        def copy_password(_button):
            row = get_selected_row()

            if row is None:
                return

            if self._copy_to_clipboard(decrypted_password_for(row), window=window):
                self.log("Copied decrypted password.")

        def capture_current_login(_button):
            self._entries = self._load_json_entries()
            changed = self._capture_current_login(source="POPUP_CAPTURE", quiet=False)

            current_username = str(config.sections["server"].get("login", "") or "").strip()
            rebuild_combo(select_username=current_username)

            if changed:
                self.log("Captured current login and updated lockbox.")
            else:
                self.log("Capture current login complete: no credential changes.")

        def reload_json(_button):
            self._entries = self._load_json_entries()
            rebuild_combo()
            self.log("Reloaded lockbox JSON.")

        def close_popup(_button):
            window.close()

        def on_show_password_toggled(_button):
            password_entry.set_visibility(show_password_check.get_active())

        def on_close(*_args):
            self._popup_window = None

        combo.connect("changed", lambda _combo: populate_fields_from_selected())
        show_password_check.connect("toggled", on_show_password_toggled)
        save_button.connect("clicked", save_or_update)
        remove_button.connect("clicked", remove_selected)
        copy_user_button.connect("clicked", copy_username)
        copy_pass_button.connect("clicked", copy_password)
        capture_button.connect("clicked", capture_current_login)
        reload_button.connect("clicked", reload_json)
        close_button.connect("clicked", close_popup)
        window.connect("close-request", on_close)

        current_username = str(config.sections["server"].get("login", "") or "").strip()
        rebuild_combo(select_username=current_username)

        window.set_child(outer)
        self._popup_window = window
        window.present()

        return False