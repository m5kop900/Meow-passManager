import sqlite3
import getpass
import os
import time
from datetime import datetime
from colorama import *
from cryptography.exceptions import InvalidTag
import secrets
import string
import pyperclip
import shutil
import json
from .validator import InputValidator
from .crypto import VaultCrypto

init(autoreset=True)


class PasswordManager:
    def __init__(self):
        self.conn = sqlite3.connect("passwd.db")
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.create_table()
        self.key = None
        self.last_activity = time.time()

    def initialize_secure_session(self):
        self.setup()
        self.unlock()

    def ensure_unlocked(self):
        if self.key is None:
            self.key = None
            self.last_activity = time.time()
            self.unlock()

    def create_table(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT,
            password BLOB NOT NULL,
            notes BLOB,
            created_at DATETIME NOT NULL,
            updated_at DATETIME,
            url BLOB,
            UNIQUE(service, username)
        );
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            key TEXT PRIMARY KEY,
            value BLOB
        );
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS verify (
            key TEXT PRIMARY KEY,
            verify BLOB
        );
        """)

        self.conn.commit()

    def setup(self):
        self.cursor.execute("SELECT value FROM vault WHERE key='salt'")

        result = self.cursor.fetchone()

        if result is None:
            salt = os.urandom(16)

            self.cursor.execute("INSERT INTO vault VALUES(?, ?)",
                                ("salt", salt))
            self.conn.commit()

        self.cursor.execute("SELECT verify FROM VERIFY WHERE key='verify'")

        resulti = self.cursor.fetchone()

        if resulti is None:
            salt = self.get_salt()

            while True:
                master1 = getpass.getpass("Create Master Password: ")
                master2 = getpass.getpass("Confirm Master Password: ")

                if master1 != master2:
                    print(Fore.RED + "Passwords don't match")
                    continue

                else:
                    print(Fore.GREEN + "Master Password Created")
                    break

            key = VaultCrypto.derive_key(master1, salt)

            verify = VaultCrypto.encrypt("vault-ok", key)

            self.cursor.execute("INSERT INTO verify VALUES(?, ?)",
                                ("verify", verify))

            self.conn.commit()

        else:
            return None

    def unlock(self):
        while True:
            master = getpass.getpass("Master Password: ")

            salt = self.get_salt()

            key = VaultCrypto.derive_key(master, salt)

            self.cursor.execute(
                "SELECT verify FROM verify WHERE key='verify'"
            )

            verify = self.cursor.fetchone()[0]

            try:
                text = VaultCrypto.decrypt(verify, key)

                if text == "vault-ok":
                    self.key = key
                    print(Fore.GREEN + "Unlocked.")
                    break

            except InvalidTag:
                print(Fore.RED + "\rWrong master password")

    def get_salt(self):
        self.cursor.execute("SELECT value FROM vault WHERE key='salt'")
        return self.cursor.fetchone()[0]

    def touch(self):
        self.last_activity = time.time()

    def copy_to_clipboard(self, text):
        try:
            pyperclip.copy(text)
            print("Copied.")
        except pyperclip.PyperclipException:
            print("Clipboard unavailable.")

    def get_password_data(self, choice, return_passid=False):
        self.ensure_unlocked()
        while True:
            pass_id = self.select_get(choice)

            if pass_id is None:
                print(Fore.YELLOW + "No password" + Style.RESET_ALL)
                return

            row = self.find_by_id(pass_id)

            data = self.get_decrypt(row)

            if return_passid:
                return pass_id, data
            else:
                return data

    def find_by_service(self, service):
        self.cursor.execute("""
            SELECT * FROM passwords
            WHERE service LIKE ?
        """, (f"%{service}%",))

        rows = self.cursor.fetchall()
        return [self.get_decrypt(row) for row in rows]

    def find_by_username(self, username):
        self.cursor.execute("""
            SELECT * FROM passwords
            WHERE username LIKE ?
        """, (f"%{username}%",))

        rows = self.cursor.fetchall()
        return [self.get_decrypt(row) for row in rows]

    def find_by_url(self, url):
        rows = self.cursor.execute("SELECT * FROM passwords").fetchall()

        results = []
        for row in rows:
            data = self.get_decrypt(row)
            if url.lower() in data["url"].lower():
                results.append(data)

        return results

    def find_by_password(self, password):
        rows = self.cursor.execute("SELECT * FROM passwords").fetchall()

        results = []
        for row in rows:
            data = self.get_decrypt(row)
            if password.lower() in data["password"].lower():
                results.append(data)

        return results

    def find_by_notes(self, notes):
        rows = self.cursor.execute("SELECT * FROM passwords").fetchall()

        results = []
        for row in rows:
            data = self.get_decrypt(row)
            if notes.lower() in data["notes"].lower():
                results.append(data)

        return results

    def find_by_id(self, meow_id):
        meow_id = int(meow_id)
        self.cursor.execute("""
            SELECT * FROM passwords
            WHERE id = ?
        """, (meow_id,))

        row = self.cursor.fetchone()

        if row is None:
            return None

        return row

    def select_get(self, choice):
        self.ensure_unlocked()
        if choice.isdigit():
            row = self.find_by_id(choice)
            return row["id"] if row else None

        else:
            result = self.find_by_service(choice)

            if not result:
                return None

            for row in result:
                self.show_print(row)

            if len(result) == 1:
                return result[0]["id"]

            username = InputValidator.get("\nUsername: ", allow_empty=True)

            for m in result:
                self.show_print(m)
                if m["username"].lower() == username.lower():
                    return m["id"]
            return None

    def get_decrypt(self, row):
        return {
            "id": row["id"],
            "service": row["service"],
            "username": row["username"],
            "password": VaultCrypto.decrypt(row["password"], self.key),
            "notes": VaultCrypto.decrypt(row["notes"], self.key) if row["notes"] else "",
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "url": VaultCrypto.decrypt(row["url"], self.key) if row["url"] else "",
        }

    def get_choice(self):
        choice = InputValidator.get("Select: ", number=True)
        self.check_lock()
        self.touch()
        return choice

    def check_lock(self):
        if self.key is None:
            self.unlock()

        if time.time() - self.last_activity >= 300:
            self.key = None
            print("Vault locked.")
            self.unlock()

        self.touch()

    def random_pass_generator(self, length):
        if length < 4:
            raise ValueError("Length must be at least 4")

        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*"

        alphabet = (
                lower +
                upper +
                digits +
                symbols
        )

        password = [
            secrets.choice(lower),
            secrets.choice(upper),
            secrets.choice(digits),
            secrets.choice(symbols),
        ]

        for _ in range(length - 4):
            password.append(secrets.choice(alphabet))

        secrets.SystemRandom().shuffle(password)

        password = "".join(password)

        return password

    def change_master_password(self):
        self.ensure_unlocked()

        salt = self.get_salt()
        shutil.copy2("passwd.db", f"passwd_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
        while True:
            master_old = getpass.getpass("Current Master Password: ")

            key_old = VaultCrypto.derive_key(master_old, salt)
            self.cursor.execute(
                "SELECT verify FROM verify WHERE key='verify'"
            )

            verify = self.cursor.fetchone()[0]

            try:
                text = VaultCrypto.decrypt(verify, key_old)

                if text == "vault-ok":
                    print(Fore.GREEN + "Ok.")

            except InvalidTag:
                print(Fore.RED + "\rWrong master password")
                continue

            master1 = getpass.getpass("Create Master Password: ")
            master2 = getpass.getpass("Confirm Master Password: ")

            if master1 != master2:
                print(Fore.RED + "Passwords don't match")
                continue

            else:
                print(Fore.GREEN + "Master Password Updated")
                break

        key = VaultCrypto.derive_key(master1, salt)

        self.cursor.execute("SELECT id,password, notes, url FROM passwords")
        i = self.cursor.fetchall()
        for row in i:
            pass_id, password, notes, url = row

            dec_password = VaultCrypto.decrypt(password, self.key)
            dec_notes = VaultCrypto.decrypt(notes, self.key) if notes else ""
            dec_url = VaultCrypto.decrypt(url, self.key) if url else ""

            enc_password = VaultCrypto.encrypt(dec_password, key)
            enc_notes = VaultCrypto.encrypt(dec_notes, key)
            enc_url = VaultCrypto.encrypt(dec_url, key)

            self.cursor.execute("""
                    UPDATE passwords
                    SET
                        password = ?,
                        notes = ?,
                        url= ?
                    WHERE id = ?
                    """, (
                enc_password,
                enc_notes,
                enc_url,
                pass_id
            ))

        verify = VaultCrypto.encrypt("vault-ok", key)

        self.cursor.execute("UPDATE verify SET verify = ? WHERE key ='verify'",
                            (verify,))
        self.key = key

        self.conn.commit()

    def add(self):
        self.ensure_unlocked()
        service = InputValidator.get("(/q for exit)Service*: ", allow_exit=True)

        if service == "/q":
            return None

        username = input("Username: ")
        password = getpass.getpass("Password*(/r for random pass word): ")
        if password == "/r":
            length = InputValidator.get("Length of password: ", number=True, min_value=4, max_value=1000000)
            password = self.random_pass_generator(length)

        print(password)
        self.copy_to_clipboard(password)

        notes = input("Notes: ")
        url = input("Url: ")

        if not self.key:
            print("Vault Locked")
            self.unlock()
            return

        enc_pass = VaultCrypto.encrypt(password, self.key)
        enc_note = VaultCrypto.encrypt(notes, self.key) if notes else None
        enc_url = VaultCrypto.encrypt(url, self.key) if url else None

        try:
            self.cursor.execute(
                "INSERT INTO passwords(service, username, password, created_at, notes, url) VALUES (?, ?, ?, ?, ?, ?)",
                (service, username, enc_pass, datetime.now().strftime("%Y-%m-%d %H:%M"), enc_note, enc_url))

            self.conn.commit()
            print(Fore.GREEN + "Password added.")

        except sqlite3.IntegrityError:
            print(Fore.RED + "A password for this service and username already exists.")

            return None

    def removei(self):
        self.ensure_unlocked()
        choice = InputValidator.get("(/q for exit)Id or Service: ", allow_neg=False, allow_exit=True)

        if choice == "/q":
            return

        result = self.get_password_data(choice, True)

        if result is None:
            return

        pass_id, data = result

        while True:
            confirm = InputValidator.get(f"\nآیا عملیات انجام شود؟ (y/n): ").lower()

            if confirm == "y":
                break
            elif confirm == "n":
                print("Cancelled.")
                return
            else:
                print("Please enter y or n.")

        self.cursor.execute("DELETE FROM passwords WHERE id = ?", (pass_id,))
        self.conn.commit()
        print(Fore.LIGHTRED_EX + "پاک شد\n" + Style.RESET_ALL)

    def edit(self):
        self.ensure_unlocked()
        self.show()

        fields = {
            1: ("service", "سرویس جدید را وارد کنید: ", False),
            2: ("username", "نام جدید را وارد کنید: ", False),
            3: ("password", "رمز عبور جدید را وارد کنید: ", True),
            4: ("notes", "یادداشت جدید را وارد کنید: ", True),
            5: ("url", "نشانی وب جدید را وارد کنید: ", True),
        }

        edit_id = self.show_password(prnt=False)

        if edit_id is None:
            return

        while True:
            kodom = InputValidator.get(Fore.CYAN +
                                       ":(۱.سرویس ۲.نام ۳.رمز عبور ۴.یادداشت ۵.نشانی وب ۶.خروج) چه چیزی را ویرایش می‌کنید؟\n",
                                       allow_neg=False,
                                       number=True
                                       )

            if kodom == 6:
                break

            if kodom not in fields:
                print("Invalid")
                continue

            column, message, encrypt = fields[kodom]

            new = InputValidator.get(message)

            if encrypt:
                new = VaultCrypto.encrypt(new, self.key)

            self.cursor.execute(
                f"UPDATE passwords SET {column} = ? WHERE id = ?",
                (new, edit_id)
            )

            self.conn.commit()

            print(Fore.LIGHTGREEN_EX + "انجام شد" + Style.RESET_ALL)

    def show_password(self, prnt=True):
        self.ensure_unlocked()
        choice = InputValidator.get("(/q for exit)Id or Service: ", allow_neg=False, allow_exit=True)

        if choice == "/q":
            return None

        result = self.get_password_data(choice, True)

        if result is None:
            return

        pass_id, data = result

        if prnt:
            self.show_print(data)
        else:
            return pass_id

    def advanced_search(self):
        self.ensure_unlocked()
        methods = {
            1: ("Service", self.find_by_service),
            2: ("Username", self.find_by_username),
            3: ("URL", self.find_by_url),
            4: ("Password", self.find_by_password),
            5: ("Notes", self.find_by_notes),
        }

        while True:
            print(Fore.MAGENTA + """
    1. Service
    2. Username
    3. URL
    4. Password
    5. Notes
    0. Back
    """)

            choice = InputValidator.get("Select: ", number=True)

            if choice == 0:
                return

            if choice not in methods:
                print("Invalid")
                continue

            name, func = methods[choice]

            text = InputValidator.get(f"{name}: ")

            results = func(text)

            if not results:
                print("Not found anything.")
                continue

            for row in results:
                self.show_print(row)

    def show(self):
        self.ensure_unlocked()
        self.cursor.execute("SELECT * FROM passwords ORDER BY service ASC")
        passwords = self.cursor.fetchall()

        if not passwords:
            print(Fore.YELLOW + "\nNo password found" + Style.RESET_ALL)
            return False

        print("\n" + Fore.BLUE, "Passwords:" + Style.RESET_ALL)
        print(Fore.LIGHTBLACK_EX + "-" * 20 + Style.RESET_ALL)
        print(Fore.CYAN + "-----------------" + Style.RESET_ALL)

        for row in passwords:
            data = self.get_decrypt(row)
            self.show_print(data)

        return True

    def show_print(self, data):
        print(
            Fore.LIGHTYELLOW_EX + "ID:" + Style.RESET_ALL,
            Fore.LIGHTMAGENTA_EX + f"[{data['id']}]" + Style.RESET_ALL,

            Fore.LIGHTCYAN_EX + "\nService:" + Style.RESET_ALL,
            Fore.BLUE + data["service"] + Style.RESET_ALL,

            Fore.YELLOW + "\nUsername:" + Style.RESET_ALL,
            data["username"],

            Fore.YELLOW + "\nPassword:" + Style.RESET_ALL,
            Fore.LIGHTRED_EX + data["password"] + Style.RESET_ALL,

            Fore.LIGHTCYAN_EX + "\nNotes:" + Style.RESET_ALL,
            Fore.MAGENTA + data["notes"] + Style.RESET_ALL,

            Fore.LIGHTBLACK_EX + "\nCreated at:" + Style.RESET_ALL,
            Fore.LIGHTBLUE_EX + str(data["created_at"]) + Style.RESET_ALL,

            Fore.LIGHTBLACK_EX + "\nUpdated at:" + Style.RESET_ALL,
            Fore.LIGHTBLUE_EX + str(data["updated_at"]) + Style.RESET_ALL,

            Fore.LIGHTBLUE_EX + "\nUrl:" + Style.RESET_ALL,
            Fore.LIGHTMAGENTA_EX + data["url"] + Style.RESET_ALL,

            Fore.CYAN + "\n-----------------" + Style.RESET_ALL
        )

    def copy_password_to_clipboard(self):
        self.ensure_unlocked()
        choice = InputValidator.get("(/q for exit)Id or Service: ", allow_neg=False, allow_exit=True)

        if choice == "/q":
            return

        data = self.get_password_data(choice)

        if data is None:
            return

        self.copy_to_clipboard(data["password"])

    def export_data(self, path):
        self.ensure_unlocked()
        self.cursor.execute("SELECT * FROM passwords")
        rows = self.cursor.fetchall()

        data = []

        for row in rows:
            decrypted = self.get_decrypt(row)

            data.append(decrypted)

        json_data = json.dumps(data, ensure_ascii=False)

        password = getpass.getpass("Create a password for the exported file: ")
        salt = os.urandom(16)

        key = VaultCrypto.derive_key(password, salt)

        encrypted = VaultCrypto.encrypt(json_data, key)

        with open(path, "wb") as f:
            f.write(salt)
            f.write(encrypted)

        print(Fore.GREEN + "\nExport Successful")

    def import_data(self, path):
        self.ensure_unlocked()
        with open(path, "rb") as f:
            salt = f.read(16)
            encrypted = f.read()
        while True:
            password = getpass.getpass("Enter password of the exported file: ")
            try:
                key = VaultCrypto.derive_key(password, salt)

                json_data = VaultCrypto.decrypt(encrypted, key)
                break

            except InvalidTag:
                print(Fore.RED + "\rWrong password")
                continue
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError:
            print(Fore.RED + "Json decode failed, maybe exported file is broken?")
            return

        for row in data:
            enc_password = VaultCrypto.encrypt(row["password"], self.key)
            enc_notes = VaultCrypto.encrypt(row["notes"], self.key) if row["notes"] else None
            enc_url = VaultCrypto.encrypt(row["url"], self.key) if row["url"] else None

            try:
                self.cursor.execute("""
                    INSERT INTO passwords(
                        service,
                        username,
                        password,
                        notes,
                        created_at,
                        updated_at,
                        url
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    row["service"],
                    row["username"],
                    enc_password,
                    enc_notes,
                    row["created_at"],
                    row["updated_at"],
                    enc_url
                ))
            except sqlite3.IntegrityError:
                print(f"Skipped: {row['service']} ({row['username']})")

        self.conn.commit()

        print(Fore.GREEN + "Import successful." + Style.RESET_ALL)

    def run(self):
        while True:
            try:
                print("\n" + Fore.LIGHTWHITE_EX + "=" * 20 + Style.RESET_ALL)
                print(Fore.LIGHTMAGENTA_EX + "   Password manager" + Style.RESET_ALL)
                print(Fore.LIGHTWHITE_EX + "=" * 20 + Style.RESET_ALL)
                print("[1]", Fore.GREEN + "Add Password" + Style.RESET_ALL)
                print("[2]", Fore.LIGHTRED_EX + "Remove Password" + Style.RESET_ALL)
                print("[3]", Fore.CYAN + "Advanced search" + Style.RESET_ALL)
                print("[4]", Fore.LIGHTCYAN_EX + "Show Password" + Style.RESET_ALL)
                print("[5]", Fore.LIGHTBLUE_EX + "Show ALL Passwords" + Style.RESET_ALL)
                print("[6]", Fore.YELLOW + "Edit" + Style.RESET_ALL)
                print("[7]", Fore.LIGHTYELLOW_EX + "Change Master Password" + Style.RESET_ALL)
                print("[8]", Fore.LIGHTBLUE_EX + "Copy password to clipboard" + Style.RESET_ALL)
                print("[9]", Fore.LIGHTMAGENTA_EX + "Generate random password" + Style.RESET_ALL)
                print("[10]", Fore.LIGHTGREEN_EX + "Export" + Style.RESET_ALL)
                print("[11]", Fore.LIGHTGREEN_EX + "Import" + Style.RESET_ALL)
                print("[0]", Fore.LIGHTBLACK_EX + "Exit" + Style.RESET_ALL)

                c = self.get_choice()

            except Exception as e:
                print("Error:", e)
                continue

            match c:
                case 1:
                    self.add()
                case 2:
                    self.removei()
                case 3:
                    self.advanced_search()
                case 4:
                    self.show_password()
                case 5:
                    self.show()
                case 6:
                    self.edit()
                case 7:
                    self.change_master_password()
                case 8:
                    self.copy_password_to_clipboard()
                case 9:
                    length = InputValidator.get("Length of password: ", number=True, min_value=4, max_value=1000000)
                    print(self.random_pass_generator(length))
                case 10:
                    path = InputValidator.get("Exported File Name: ")
                    self.export_data(path)
                case 11:
                    path = InputValidator.get("File path: ")
                    self.import_data(path)
                case 0:
                    print(Fore.GREEN + "خروج از برنامه. خدانگهدار!" + Style.RESET_ALL)
                    break
                case _:
                    print("\n", Fore.LIGHTRED_EX + "عملیات نامعتبر" + Style.RESET_ALL)


if __name__ == "__main__":
    app = PasswordManager()
    app.run()