import os
import hashlib
import getpass
import base64
from cryptography.fernet import Fernet
import json
from simple_term_menu import TerminalMenu
from termcolor import colored
import time


danger = colored("[", 'red') + colored("!", 'white') + colored("]", 'red')
calm = colored("[", 'magenta') + colored("~", 'white') + colored("]", 'magenta')
good = colored("[", 'green') + colored("+", 'white') + colored("]", 'green')

PASSKEY_FILE = 'passkey.jiren'
DOC_STORAGE_KEY = 'documents'

def print_banner(text, color='cyan'):

    banner = colored("-" * (len(text) + 4), color)
    print(f"\n{banner}")
    print(f"{colored('|', color)} {colored(text, color)} {colored('|', color)}")
    print(f"{banner}\n")

def print_divider(color='blue'):

    print(colored("=" * 80, color))

def delayed_print(text, delay=0.05):

    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(salt + pwdhash).decode('utf-8')

def check_password(stored_password: str, provided_password: str) -> bool:
    decoded = base64.b64decode(stored_password.encode('utf-8'))
    salt, stored_pwdhash = decoded[:16], decoded[16:]
    pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return pwdhash == stored_pwdhash

def load_passkey():
    if not os.path.exists(PASSKEY_FILE):
        return None
    with open(PASSKEY_FILE, 'rb') as file:
        return file.read()

def save_passkey(data: bytes):
    with open(PASSKEY_FILE, 'wb') as file:
        file.write(data)

def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'some_salt', 100000))

def encrypt_data(data: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    return Fernet(key).decrypt(encrypted_data).decode('utf-8')

def initialize_passkey():
    print_banner("Initializing Passkey", 'green')
    password = getpass.getpass(calm + ' Create a new password: ')
    confirm_password = getpass.getpass(calm + ' Confirm your password: ')
    
    if password != confirm_password:
        print(danger + " Passwords do not match. Try again.")
        return
    
    hashed_password = hash_password(password)
    encryption_key = generate_key(password)
    
    data = {'password': hashed_password, DOC_STORAGE_KEY: {}}
    save_passkey(encrypt_data(json.dumps(data), encryption_key))
    delayed_print(good + colored(" Passkey created successfully.", 'green'))

def validate_password():
    print_banner("Validate Passkey", 'white')
    stored_data = load_passkey()
    if not stored_data:
        delayed_print(calm + " Passkey file not found. Please initialize it first.")
        return False, None
    
    password = getpass.getpass(calm + ' Enter your password: ')
    encryption_key = generate_key(password)
    
    try:
        decrypted_data = decrypt_data(stored_data, encryption_key)
        stored_password = json.loads(decrypted_data)['password']
        
        if check_password(stored_password, password):
            delayed_print(good + " Access granted.", 0.05)
            return True, encryption_key
        else:
            delayed_print(danger + " Incorrect password.", 0.05)
            return False, None
    except Exception:
        delayed_print(danger + colored(" Failed to decrypt passkey. Possible file corruption.", 'red'))
        return False, None

def load_documents(encryption_key: bytes) -> dict:
    stored_data = load_passkey()
    decrypted_data = decrypt_data(stored_data, encryption_key)
    return json.loads(decrypted_data).get(DOC_STORAGE_KEY, {})

def save_documents(documents: dict, encryption_key: bytes):
    stored_data = load_passkey()
    decrypted_data = decrypt_data(stored_data, encryption_key)
    data = json.loads(decrypted_data)
    data[DOC_STORAGE_KEY] = documents
    save_passkey(encrypt_data(json.dumps(data), encryption_key))

def create_document(encryption_key: bytes):
    documents = load_documents(encryption_key)
    print_banner("Create Document", 'green')
    doc_name = input(good + " Enter the document name: ")
    
    if doc_name in documents:
        delayed_print(danger + " Document with this name already exists.")
        return
    
    delayed_print(good + " Enter the content of the document. Type ':wq' on a new line to save and exit.")
    lines = []
    while True:
        line = input()
        if line.strip() == ':wq':
            break
        lines.append(line)
    
    documents[doc_name] = '\n'.join(lines)
    save_documents(documents, encryption_key)
    delayed_print(good + f" Document '{doc_name}' saved successfully.")

def edit_document(encryption_key: bytes):
    documents = load_documents(encryption_key)
    print_banner("Edit Document", 'yellow')
    doc_name = input(calm + " Enter the document name to edit: ")
    
    if doc_name not in documents:
        delayed_print(danger + " Document not found.")
        return
    
    print(calm + " Current content:")
    print(good + colored("-" * 35, 'green'))
    delayed_print(documents[doc_name], 0.01)
    print(good + colored("-" * 35, 'green'))
    delayed_print("\n" + danger + " Enter the new content. Type ':wq' on a new line to save and exit.")
    
    lines = []
    while True:
        line = input()
        if line.strip() == ':wq':
            break
        lines.append(line)
    
    documents[doc_name] = '\n'.join(lines)
    save_documents(documents, encryption_key)
    delayed_print(good + colored(f" Document '{doc_name}' updated successfully.", 'green'))

def list_documents(encryption_key: bytes):
    documents = load_documents(encryption_key)
    print_banner("Documents", 'cyan')
    
    if not documents:
        delayed_print(calm + " No documents found.")
        return
    
    options = [f"{doc_name}" for doc_name in documents]
    terminal_menu = TerminalMenu(options, title="Select a Document:", menu_cursor="<< ", menu_cursor_style=("fg_red", "bg_black", "bold"))
    choice = terminal_menu.show()
    
    if choice is not None:
        doc_name = options[choice]
        print_banner(f"Content of '{doc_name}'", 'white')
        delayed_print(documents[doc_name], 0.02)
        print_divider('cyan')
        input("\n" + good + " Press Enter to return to the menu.")
        os.system('cls' if os.name == 'nt' else 'clear')

def delete_document(encryption_key: bytes):
    documents = load_documents(encryption_key)
    print_banner("Delete Document", 'red')
    doc_name = input(danger + colored(" Enter the document name to delete: ", 'red'))
    
    if doc_name not in documents:
        delayed_print(danger + " Document not found.")
        return
    
    confirm = input(danger + colored(f" Are you sure you want to delete '{doc_name}'? This action cannot be undone. (yes/no): ", 'red'))
    if confirm.lower() == 'yes':
        del documents[doc_name]
        save_documents(documents, encryption_key)
        delayed_print(danger + f" Document '{doc_name}' deleted successfully.")
    else:
        delayed_print(good + " Delete operation cancelled.")

def main_menu(encryption_key: bytes):
    menu_items = ["Create a Document", "Edit a Document", "List Documents", "Delete a Document", "Exit"]
    terminal_menu = TerminalMenu(menu_items, title="-:", menu_cursor=">> ", menu_cursor_style=("fg_red", "bg_black", "bold"))
    
    while True:
        print_banner("Main Menu", 'white')
        choice = terminal_menu.show()
        if choice == 0:
            create_document(encryption_key)
        elif choice == 1:
            edit_document(encryption_key)
        elif choice == 2:
            list_documents(encryption_key)
        elif choice == 3:
            delete_document(encryption_key)
        elif choice == 4:
            print_banner("Goodbye!", 'green')
            break

if __name__ == "__main__":
    print_banner("The JiN", 'white')
    if not os.path.exists(PASSKEY_FILE):
        initialize_passkey()
    else:
        success, encryption_key = validate_password()
        if success:
            main_menu(encryption_key)
