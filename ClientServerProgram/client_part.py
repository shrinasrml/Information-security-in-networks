import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import hashlib
import socket
import secrets
import threading
from other_client import *

class ClientApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Клиент")
        self.root.geometry("300x250")
        self.root.configure(bg="#003366")
        self.is_authenticated = False

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect_to_server()

        self.session_key = None

        self.received_file = None
        self.file_to_sign = None

        self.public_key, self.private_key = generate_rsa_keys()
        self.other_public_key = None

        self.main_frame = tk.Frame(self.root, bg="#003366")
        self.main_frame.pack(pady=20)

        self.create_button(self.main_frame, "Авторизация", self.open_auth_window)
        self.create_button(self.main_frame, "Окно чата клиента", self.open_chat_window)
        self.create_button(self.main_frame, "Выход", self.root.quit)

        self.chat_area = None
        self.root.mainloop()

    def create_button(self, parent, text, command):
        button = tk.Button(
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
        )
        button.pack(fill=tk.X, pady=10)
        return button

    def connect_to_server(self):
        try:
            self.client_socket.connect(("127.0.0.1", 9999))
            print("Сервер подключен.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удается подключиться к серверу: {e}")
            self.client_socket = None

    def open_auth_window(self):
        window = tk.Toplevel(self.root)
        window.title("Авторизация")
        window.geometry("400x250")
        window.configure(bg="#003366")

        tk.Label(window, text="Авторизация", bg="#003366", fg="white", font=("Arial", 16, "bold")).pack(pady=10)

        tk.Label(window, text="Логин", bg="#003366", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        entry_username = tk.Entry(window, font=("Arial", 12))
        entry_username.pack(pady=5)

        tk.Label(window, text="Пароль", bg="#003366", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        entry_password = tk.Entry(window, show="*", font=("Arial", 12))
        entry_password.pack(pady=5)

        def authenticate():
            username = entry_username.get()
            password = entry_password.get()
            if username and password:
                try:
                    client = self.client_socket
                    client.send(username.encode())
                    response = client.recv(1024).decode()

                    if response == "User not found":
                        messagebox.showerror("Ошибка", "Пользователь не найден!")
                    else:
                        challenge = response
                        hashed_password = hashlib.md5(password.encode()).hexdigest()
                        super_hash = hashlib.md5((hashed_password + challenge).encode()).hexdigest()
                        client.send(super_hash.encode())
                        result = client.recv(1024).decode()
                        if result == "AUTH_SUCCESS":
                            messagebox.showinfo("Внимание", "Авторизация прошла успешно!")
                            self.is_authenticated = True
                            window.destroy()
                        else:
                            messagebox.showerror("Ошибка", "Ошибка авторизации!")
                except Exception as e:
                    messagebox.showerror("Ошибка", str(e))
            else:
                messagebox.showerror("Ошибка", "Пожалуйста, заполните все поля!")

        tk.Button(window, text="Войти", bg="#7FDBFF", fg="black", font=("Arial", 12, "bold"),
                  activebackground="#39CCCC", activeforeground="white", command=authenticate).pack(pady=20)

    def open_chat_window(self):
        def handle_diffie_hellman_exchange():
            data = self.client_socket.recv(1024).decode()
            p, g, A = map(int, data.split(","))

            b = secrets.randbits(64) | 1
            B = pow(g, b, p)

            self.client_socket.send(str(B).encode())

            self.session_key = pow(A, b, p)
            print(f"Session Key: {self.session_key}")

        def exchange_rsa_keys():
            client_public_key = f"{self.public_key[0]},{self.public_key[1]}"
            self.client_socket.send(client_public_key.encode())

            server_public_key = self.client_socket.recv(1024).decode()
            e, n = map(int, server_public_key.split(","))
            self.other_public_key = (e, n)
            print("Server RSA Public Key:", self.other_public_key)

        if not self.is_authenticated:
            messagebox.showerror("Ошибка", "Для доступа к чату вам необходимо пройти проверку подлинности.")
            return

        handle_diffie_hellman_exchange()
        exchange_rsa_keys()

        chat_window = tk.Toplevel(self.root)
        chat_window.title("Окно чата клиента")
        chat_window.geometry("1000x500")
        chat_window.configure(bg="#003366")

        self.chat_area = scrolledtext.ScrolledText(chat_window, width=80, height=20, font=("Arial", 12), bg="#003366",
                                                   fg="white", bd=3, relief="sunken")
        self.chat_area.pack(pady=10)

        input_area = tk.Entry(chat_window, width=50, font=("Arial", 12), bd=2, relief="sunken")
        input_area.pack(side=tk.LEFT, padx=10, pady=10)

        def send_message():
            message = input_area.get()
            if message and self.client_socket:
                try:
                    current_time = datetime.datetime.now().strftime("%H:%M:%S")
                    encrypted_message = rc4(str(self.session_key), message)
                    print(f"RC4 Encrypted Message: {encrypted_message}")
                    self.client_socket.send(encrypted_message.encode())
                    self.chat_area.insert(tk.END, f"{current_time} Вы: {message}\n")
                    input_area.delete(0, tk.END)
                except Exception as e:
                    messagebox.showerror("Ошибка", str(e))

        def send_file():
            file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, "r", encoding="utf-8") as f:
                    file_data = f.read()
                    self.file_to_sign = hashlib.md5(file_data.encode()).hexdigest()
                    self.client_socket.send(str("FILE").encode())
                    encrypted_file = rsa_encrypt(file_data, self.other_public_key)
                    print(f"Encrypted File: {encrypted_file}")
                    self.client_socket.send(str(encrypted_file).encode())
                    messagebox.showinfo("Сервер", "Файл отправлен с зашифрованным хэшем.")

        send_button = tk.Button(chat_window, text="Отправить", bg="#7FDBFF", fg="black", font=("Arial", 12, "bold"),
                                 activebackground="#39CCCC", activeforeground="white", height=2,
            width=15, command=send_message)
        send_button.pack(side=tk.RIGHT, padx=5, pady=20)

        tk.Button(chat_window, text="Отправить файл", bg="#7FDBFF", fg="black", font=("Arial", 12, "bold"),
                  activebackground="#39CCCC", activeforeground="white", height=2,
            width=15, command=send_file).pack(side=tk.RIGHT, padx=5, pady=20)

        self.sign_file_button = tk.Button(chat_window, text="Подписать файл", bg="#7FDBFF", fg="black", font=("Arial", 12, "bold"),
                                          activebackground="#39CCCC", activeforeground="white", height=2,
            width=15, command=self.sign_received_file)
        self.sign_file_button.pack(side=tk.RIGHT, padx=5, pady=20)
        self.sign_file_button.config(state=tk.DISABLED)

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(1024).decode()
                if data == "FILE":
                    encrypted_file = self.client_socket.recv(4096).decode()
                    print(f"Received Encrypted File: {encrypted_file}")
                    self.handle_received_file(encrypted_file)
                elif data == 'SIGNATURE':
                    encrypted_signature = self.client_socket.recv(16384).decode()
                    print(f"Received Encrypted Signature: {encrypted_signature}")
                    self.handle_signature(encrypted_signature)
                else:
                    current_time = datetime.datetime.now().strftime("%H:%M:%S")
                    decrypted_message = rc4(str(self.session_key), data)
                    print(f"RC4 Decrypted Message: {decrypted_message}")
                    self.chat_area.insert(tk.END, f"{current_time} Сервер: {decrypted_message}\n")
            except:
                break

    def handle_received_file(self, encrypted_file):
        try:
            file_data = rsa_decrypt(eval(encrypted_file), self.private_key)
            with open("received_file_client.txt", "w", encoding="utf-8") as f:
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
        encrypted_hash = rsa_encrypt(file_hash, self.other_public_key)

        self.client_socket.send("SIGNATURE".encode())
        self.client_socket.send(str(encrypted_hash).encode())
        print(f"Encrypted Signature Sent: {encrypted_hash}")
        messagebox.showinfo("Сервер", "Файл подписан, подпись отправлена клиенту!")

    def handle_signature(self, encrypted_signature):
        try:
            decrypted_hash = rsa_decrypt(eval(encrypted_signature), self.private_key)
            if self.file_to_sign == decrypted_hash:
                messagebox.showinfo("Внимание", "Подпись успешно подтверждена!")
            else:
                messagebox.showerror("Ошибка", "Не удалось подтвердить подпись!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при проверке подписи: {e}")


if __name__ == "__main__":
    ClientApp()
