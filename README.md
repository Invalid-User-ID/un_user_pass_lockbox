Local username/password lockbox for Nicotine+ login profiles with popup-based management and obfuscated JSON storage.

Commands:
  /lockbox
    Sync current Nicotine+ login and open the LockBox popup

  /lockboxsync
    Sync current Nicotine+ login without opening the popup

Popup Features:
  - View saved usernames in a dropdown
  - Add or update username/password/note entries
  - Remove selected saved username
  - Copy selected username
  - Copy decrypted password to clipboard
  - Capture current Nicotine+ login manually
  - Reload lockbox.json from disk

Auto-Capture:
  - Capture current login on plugin load
  - Capture current login after server connect
  - Capture current login on shutdown/plugin unload
  - Optional silent polling for login/password changes
  - Updates saved password when the same username uses a new password

Storage:
  - Saves entries to lockbox.json
  - Username is stored plaintext
  - Notes are stored plaintext
  - Password is stored as an obfuscated password_enc field
  - Master key is stored in plaintext plugin settings

Security Notes:
  - This is not a real password manager
  - Password storage uses dependency-free XOR + base64 obfuscation
  - Changing the master key after saving entries could prevent password recovery
  - Intended for local convenience and account user/pass storage, not high-security storage

Designed for:
  - Nicotine+ 3.3.10
