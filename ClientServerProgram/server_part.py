import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import hashlib
import threading
import socket
import secrets
from other_server import *
from DataBase import *


class ServerApp:
    def __init__(self):
        self.db = UserDatabase()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("127.0.0.1", 9999))
        self.server_socket.listen(1)

        self.client_connection = None
        self.session_key = None
        self.is_authenticated = False

        self.file_to_sign = None
        self.received_file = None

        self.public_key, self.private_key = generate_rsa_keys()
        self.other_public_key = None

        self.root = tk.Tk()
        self.root.title("Сервер")
        self.root.geometry("400x350")
        self.root.configure(bg="#003366")

        self.main_frame = tk.Frame(self.root, bg="#003366")
        self.main_frame.pack(pady=30)

        menu = tk.Menu(self.root)
        self.root.config(menu=menu)

        buttons = [
            ("Регистрация", self.open_register_window),
            ("Авторизация", self.wait_for_login),
            ("Окно чата сервера", self.open_chat_window),
            ("Выход", self.root.quit)
        ]

        for text, command in buttons:
            self.create_button(self.main_frame, text, command)

        self.chat_area = None
        self.server_thread = None
        self.root.mainloop()

    def create_button(self, parent, text, command):
        tk.Button(
            parent,
            text=text,
            command=command,
            bg="#7FDBFF",
            fg="black",
            font=("Arial", 12, "bold"),
            activebackground="#39CCCC",
            activeforeground="white",
            height=2,
            width=25
        ).pack(fill=tk.X, pady=10)

    def open_register_window(self):
        window = tk.Toplevel(self.root)
        window.title("Регистрация")
        window.geometry("400x400")

        tk.Label(window, text="Регистрация нового пользователя", bg="#003366", fg="white",
                 font=("Arial", 16, "bold")).pack(pady=10)

        tk.Label(window, text="Логин", bg="#003366", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        entry_username = tk.Entry(window, font=("Arial", 12))
        entry_username.pack(pady=5)

        tk.Label(window, text="Пароль", bg="#003366", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        entry_password = tk.Entry(window, show="*", font=("Arial", 12))
        entry_password.pack(pady=5)

        def submit():
            username = entry_username.get()
            password = entry_password.get()
            if username and password:
                hashed_password = hashlib.md5(password.encode()).hexdigest()
                if self.db.add_user(username, hashed_password):
                    messagebox.showinfo("Внимание", "Пользователь успешно зарегистрирован!")
                    window.destroy()
                else:
                    messagebox.showerror("Ошибка", "Пользователь уже существует!")
            else:
                messagebox.showerror("Ошибка", "Введите действительные данные!")

        tk.Button(window, text="Регистрация", bg="#7FDBFF", fg="black", font=("Arial", 12, "bold"),
                  activebackground="#39CCCC", activeforeground="white", command=submit).pack(pady=20)

        def show_users_in_console():
            self.show_users_list_in_console()

        tk.Button(window, text="Показать всех пользователей", bg="#FF851B", fg="black", font=("Arial", 12, "bold"),
                  activebackground="#FF4136", activeforeground="white", command=show_users_in_console).pack(pady=10)

    def show_users_list_in_console(self):
        """Метод для вывода списка всех пользователей в консоль"""
        users = self.db.get_all_users()

        if users:
            print("Список зарегистрированных пользователей:")
            for user in users:
                print(user)
        else:
            print("Нет зарегистрированных пользователей")

    def wait_for_login(self):
        messagebox.showinfo("Сервер", "Сервер ожидает входа в систему")
        self.client_connection, _ = self.server_socket.accept()
        threading.Thread(target=self.handle_login).start()

    def handle_login(self):
        username = self.client_connection.recv(1024).decode()

        if not self.db.user_exists(username):
            self.client_connection.send(b"User not found")
            self.client_connection.close()
        else:
            challenge = hashlib.md5(secrets.token_hex(16).encode()).hexdigest()
            self.client_connection.send(challenge.encode())

            hashed_password = self.db.get_password(username)
            response = self.client_connection.recv(1024).decode()
            super_hash = hashlib.md5((hashed_password + challenge).encode()).hexdigest()

            if response == super_hash:
                self.client_connection.send(b"AUTH_SUCCESS")
                self.is_authenticated = True
                messagebox.showinfo("Сервер", f"Пользователь {username} успешно прошел проверку подлинности!")
            else:
                self.client_connection.send(b"AUTH_FAILED")
                self.client_connection.close()

    def handle_diffie_hellman_exchange(self):
        p, g = generate_diffie_hellman_parameters()
        a = secrets.randbits(64) | 1
        A = pow(g, a, p)

        self.client_connection.send(f"{p},{g},{A}".encode())

        B = int(self.client_connection.recv(1024).decode())

        self.session_key = pow(B, a, p)
        messagebox.showinfo("Сервер", f"Сгенерированный общий сеансовый ключ!")

    def open_chat_window(self):
        if not self.is_authenticated:
            messagebox.showerror("Ошибка", "Сначала пройдите авторизацию!")
            return

        def exchange_rsa_keys():
            server_public_key = self.client_connection.recv(1024).decode()
            e, n = map(int, server_public_key.split(','))
            self.other_public_key = (e, n)
            print("Client RSA Public Key:", self.other_public_key)

            server_public_key = f"{self.public_key[0]},{self.public_key[1]}"
            self.client_connection.send(server_public_key.encode())

        self.handle_diffie_hellman_exchange()
        exchange_rsa_keys()

        chat_window = tk.Toplevel(self.root)
        chat_window.title("Окно чата сервера")
        chat_window.geometry("1000x500")
        chat_window.configure(bg="#003366")

        self.chat_area = scrolledtext.ScrolledText(chat_window, width=80, height=20, font=("Arial", 12), bg="#003366",
                                                   fg="white", bd=3, relief="sunken")
        self.chat_area.pack(pady=10)

        input_area = tk.Entry(chat_window, width=50, font=("Arial", 12), bd=2, relief="sunken")
        input_area.pack(side=tk.LEFT, padx=10, pady=10)

        def send_message():
            message = input_area.get()
            if message:
                current_time = datetime.datetime.now().strftime("%H:%M:%S")
                encrypted_message = rc4(str(self.session_key), message)
                print(f"Encrypted message: {encrypted_message}")
                self.client_connection.send(encrypted_message.encode())
                self.chat_area.insert(tk.END, f"{current_time} Сервер: {message}\n")
                input_area.delete(0, tk.END)

        def send_file():
            file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, "r", encoding="utf-8") as f:
                    file_data = f.read()
                    self.file_to_sign = hashlib.md5(file_data.encode()).hexdigest()
                    self.client_connection.send(str("FILE").encode())
                    encrypted_file = rsa_encrypt(file_data, self.other_public_key)
                    print(f"Encrypted file: {encrypted_file}")
                    self.client_connection.send(str(encrypted_file).encode())
                    messagebox.showinfo("Сервер", "Файл отправлен с зашифрованным хэшем!")

        send_button = tk.Button(chat_window, text="Отправить", bg="#7FDBFF", fg="black", font=("Arial", 12, "bold"),
                                activebackground="#39CCCC", activeforeground="white", height=2,
                                width=15, command=send_message)
        send_button.pack(side=tk.RIGHT, padx=5, pady=20)

        tk.Button(chat_window, text="Отправить файл", bg="#7FDBFF", fg="black", font=("Arial", 12, "bold"),
                  activebackground="#39CCCC", activeforeground="white", height=2,
                  width=15, command=send_file).pack(side=tk.RIGHT, padx=5, pady=20)

        self.sign_file_button = tk.Button(chat_window, text="Подписать файл", bg="#7FDBFF", fg="black",
                                          font=("Arial", 12, "bold"),
                                          activebackground="#39CCCC", activeforeground="white", height=2,
                                          width=15, command=self.sign_received_file)
        self.sign_file_button.pack(side=tk.RIGHT, padx=5, pady=20)
        self.sign_file_button.config(state=tk.DISABLED)

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                data = self.client_connection.recv(1024).decode()
                if data == "FILE":
                    encrypted_file = self.client_connection.recv(4096).decode()
                    print(f"Received encrypted file: {encrypted_file}")
                    self.handle_received_file(encrypted_file)
                elif data == 'SIGNATURE':
                    encrypted_signature = self.client_connection.recv(16384).decode()
                    print(f"Received encrypted signature: {encrypted_signature}")
                    self.handle_signature(encrypted_signature)
                else:
                    current_time = datetime.datetime.now().strftime("%H:%M:%S")
                    print(f"Received encrypted message: {data}")
                    decrypted_message = rc4(str(self.session_key), data)
                    self.chat_area.insert(tk.END, f"{current_time} Клиент: {decrypted_message}\n")
            except:
                break

    def handle_received_file(self, encrypted_file):
        try:
            print(f"Decrypting file: {encrypted_file}")
            file_data = rsa_decrypt(eval(encrypted_file), self.private_key)
            with open("received_file_server.txt", "w", encoding="utf-8") as f:
                f.write(file_data)
                messagebox.showinfo("Сервер", "Файл успешно получен!")

            self.received_file = file_data
            self.sign_file_button.config(state=tk.NORMAL)

        except Exception as e:
            messagebox.showerror("Сервер", f"Обработка ошибок в полученном файле: {e}")

    def sign_received_file(self):
        if self.received_file is None:
            messagebox.showerror("Ошибка", "Файл для подписи не получен!")
            return

        self.sign_file_button.config(state=tk.DISABLED)

        file_hash = hashlib.md5(self.received_file.encode()).hexdigest()
        encrypted_file = rsa_encrypt(file_hash, self.other_public_key)
        print(f"Encrypted signature: {encrypted_file}")
        self.client_connection.send("SIGNATURE".encode())
        self.client_connection.send(str(encrypted_file).encode())
        messagebox.showinfo("Сервер", "Файл подписан, подпись отправлена клиенту!")

    def handle_signature(self, encrypted_signature):
        try:
            decrypted_signature = rsa_decrypt(eval(encrypted_signature), self.private_key)

            if self.file_to_sign and decrypted_signature == self.file_to_sign:
                messagebox.showinfo("Сервер", "Подпись успешно подтверждена! Файл является подлинным.")
            else:
                messagebox.showerror("Сервер", "Не удалось подтвердить подпись! Возможно, файл поврежден.")
        except Exception as e:
            messagebox.showerror("Сервер", f"Ошибка обработки подписи: {e}")
            print(e)

if __name__ == "__main__":
    ServerApp()
