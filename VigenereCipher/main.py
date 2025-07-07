import tkinter as tk
from tkinter import filedialog, messagebox
import re
from collections import Counter
import math

class VigenerCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Главное меню")

        self.language = tk.StringVar(value="ru")

        # Главное меню с кнопками для открытия отдельных окон
        tk.Button(root, text="Шифровка и расшифровка текста", command=self.open_encryption_decryption_text_window).pack(pady=10)
        tk.Button(root, text="Шифровка и расшифровка текста из файла", command=self.open_encryption_decryption_file_window).pack(pady=10)
        tk.Button(root, text="Взлом шифра", command=self.open_hack_cipher_window).pack(pady=10)

    def validate_text(self, text):
        if self.language.get() == "ru":
            allowed_chars = re.compile(r'^[а-яёЁА-Я]*$')
        else:
            allowed_chars = re.compile(r'^[a-zA-Z]*$')
        if not allowed_chars.search(text):
            messagebox.showerror("Ошибка",
                                 f"Текст должен содержать только символы на {'русском' if self.language.get() == 'ru' else 'английском'} языке.")
            return False
        return True

    def open_encryption_decryption_text_window(self):
        # Окно для шифрования и дешифрования текста
        window = tk.Toplevel(self.root)
        window.title("Шифровка и расшифровка текста")

        # Добавляем переключатель для выбора языка
        tk.Label(window, text="Выберите язык:").grid(row=0, column=0)
        tk.Radiobutton(window, text="Русский", variable=self.language, value="ru").grid(row=0, column=1)
        tk.Radiobutton(window, text="Английский", variable=self.language, value="en").grid(row=0, column=2)

        # Поле для исходного сообщения
        tk.Label(window, text="Исходное сообщение:").grid(row=1, column=0)
        entry_message = tk.Entry(window, width=50)
        entry_message.grid(row=1, column=1, columnspan=2)

        # Поле для ввода ключа
        tk.Label(window, text="Ключ:").grid(row=2, column=0)
        entry_key = tk.Entry(window, width=15)
        entry_key.grid(row=2, column=1)

        # Поле для вывода зашифрованного и расшифрованного сообщений
        tk.Label(window, text="Зашифрованное сообщение:").grid(row=3, column=0)
        entry_encrypted = tk.Entry(window, width=50)
        entry_encrypted.grid(row=3, column=1, columnspan=2)

        tk.Label(window, text="Расшифрованное сообщение:").grid(row=5, column=0)
        entry_decrypted = tk.Entry(window, width=50)
        entry_decrypted.grid(row=5, column=1, columnspan=2)

        # Кнопки для шифровки и расшифровки
        tk.Button(window, text="Зашифровать",
                  command=lambda: self.encrypt_message(entry_message, entry_key, entry_encrypted)).grid(row=4, column=1)
        tk.Button(window, text="Расшифровать",
                  command=lambda: self.decrypt_message(entry_encrypted, entry_key, entry_decrypted)).grid(row=6, column=1)

    def open_encryption_decryption_file_window(self):
        # Окно для работы с файлами
        window = tk.Toplevel(self.root)
        window.title("Шифровка и расшифровка текста из файла")

        self.loaded_file_text = ""
        self.processed_text = ""  # Хранит зашифрованный или расшифрованный текст

        # Добавляем переключатель для выбора языка
        tk.Label(window, text="Выберите язык:").grid(row=0, column=0)
        tk.Radiobutton(window, text="Русский", variable=self.language, value="ru").grid(row=0, column=1)
        tk.Radiobutton(window, text="Английский", variable=self.language, value="en").grid(row=0, column=2)

        # Кнопка для загрузки файла
        tk.Button(window, text="Загрузить файл", command=self.load_file).grid(row=1, column=0, pady=10)

        # Поле для ввода ключа
        tk.Label(window, text="Ключ:").grid(row=2, column=0)
        self.entry_key_file = tk.Entry(window, width=15)
        self.entry_key_file.grid(row=2, column=1, pady=10)

        # Переключатель между шифрованием и расшифровкой
        self.action_choice = tk.StringVar(value="encrypt")
        tk.Radiobutton(window, text="Зашифровать", variable=self.action_choice, value="encrypt").grid(row=3, column=0)
        tk.Radiobutton(window, text="Расшифровать", variable=self.action_choice, value="decrypt").grid(row=3, column=1)

        # Кнопка для выполнения действия (шифрования или расшифровки)
        tk.Button(window, text="Выполнить", command=self.process_file).grid(row=4, column=0, pady=10)

        # Кнопка для сохранения результата
        tk.Button(window, text="Сохранить файл", command=self.save_file).grid(row=4, column=1, pady=10)

    def open_hack_cipher_window(self):
        # Окно для взлома шифра
        window = tk.Toplevel(self.root)
        window.title("Взлом шифра")

        # Кнопка для выбора файла и взлома
        tk.Button(window, text="Выбрать файл", command=self.load_file).grid(row=0, column=0)
        tk.Button(window, text="Взломать шифр", command=self.hack_cipher).grid(row=0, column=1)

    def vigener_encrypt(self, text, key, alphabet_size):
        result = []
        key = key.lower().replace('ё', 'е')  # Убираем 'ё'
        key_len = len(key)
        text = text.lower().replace('ё', 'е')  # Преобразуем текст

        for i, char in enumerate(text):
            if char.isalpha():
                base = ord('а') if 'а' <= char <= 'я' else ord('a')
                shift = ord(key[i % key_len]) - base
                result.append(chr((ord(char) - base + shift) % alphabet_size + base))
            else:
                result.append(char)
        return ''.join(result)

    def vigener_decrypt(self, text, key, alphabet_size):
        result = []
        key = key.lower().replace('ё', 'е')
        key_len = len(key)
        text = text.lower().replace('ё', 'е')

        for i, char in enumerate(text):
            if char.isalpha():
                base = ord('а') if 'а' <= char <= 'я' else ord('a')
                shift = ord(key[i % key_len]) - base
                result.append(chr((ord(char) - base - shift) % alphabet_size + base))
            else:
                result.append(char)
        return ''.join(result)

    def encrypt_message(self, entry_message, entry_key, entry_encrypted):
        try:
            message = entry_message.get()
            key = entry_key.get()

            if not message or not key:
                messagebox.showerror("Ошибка", "Сообщение и ключ не должны быть пустыми.")
                return
            if message.startswith(" ") or " " in message.strip():
                messagebox.showerror("Ошибка", "В тексте не должен быть пробел.")
                return
            if key.startswith(" ") or " " in key.strip():
                messagebox.showerror("Ошибка", "В ключе не должен быть пробел.")
                return
            if not self.validate_text(message) or not self.validate_text(key):
                return

            alphabet_size = 32 if self.language.get() == "ru" else 26
            encrypted = self.vigener_encrypt(message, key, alphabet_size)
            entry_encrypted.delete(0, tk.END)
            entry_encrypted.insert(tk.END, encrypted)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")

    def decrypt_message(self, entry_encrypted, entry_key, entry_decrypted):
        try:
            encrypted_message = entry_encrypted.get().strip()
            key = entry_key.get()

            if not encrypted_message or not key:
                messagebox.showerror("Ошибка", "Сообщение и ключ не должны быть пустыми.")
                return
            if key.startswith(" ") or " " in key.strip():
                messagebox.showerror("Ошибка", "В ключе не должен быть пробел.")
                return
            if not self.validate_text(encrypted_message) or not self.validate_text(key):
                return

            alphabet_size = 32 if self.language.get() == "ru" else 26
            decrypted = self.vigener_decrypt(encrypted_message, key, alphabet_size)
            entry_decrypted.delete(0, tk.END)
            entry_decrypted.insert(tk.END, decrypted)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")

    def load_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as file:
                self.loaded_file_text = file.read()
            if not self.validate_text(self.loaded_file_text):
                self.loaded_file_text = ""
            else:
                messagebox.showinfo("Файл загружен", "Файл успешно загружен.")

    def process_file(self):
        if not self.loaded_file_text:
            messagebox.showerror("Ошибка", "Сначала загрузите файл.")
            return

        try:
            key = self.entry_key_file.get()
            if not key:
                messagebox.showerror("Ошибка", "Ключ не может быть пустым.")
                return
            if key.startswith(" ") or " " in key.strip():
                messagebox.showerror("Ошибка", "В ключе не должен быть пробел.")
                return
            if not self.validate_text(key):
                return

            alphabet_size = 32 if self.language.get() == "ru" else 26

            if self.action_choice.get() == "encrypt":
                self.processed_text = self.vigener_encrypt(self.loaded_file_text, key, alphabet_size)
                messagebox.showinfo("Готово", "Файл успешно зашифрован.")
            elif self.action_choice.get() == "decrypt":
                self.processed_text = self.vigener_decrypt(self.loaded_file_text, key, alphabet_size)
                messagebox.showinfo("Готово", "Файл успешно расшифрован.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")

    def save_file(self):
        if self.processed_text:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt")
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(self.processed_text)
                messagebox.showinfo("Файл сохранён", "Результат успешно сохранён.")
        else:
            messagebox.showwarning("Нет данных", "Нет данных для сохранения.")

    def hack_cipher(self):
        if not self.loaded_file_text:
            messagebox.showerror("Ошибка", "Сначала загрузите файл с зашифрованным текстом.")
            return

        try:
            language = self.language.get()
            alphabet_size = 32 if language == "ru" else 26

            # Шаг 1: Найти длину ключа методом индекса совпадений
            key_length = self.find_key_length(self.loaded_file_text, alphabet_size)
            if not key_length:
                messagebox.showerror("Ошибка", "Не удалось определить длину ключа.")
                return

            # Шаг 2: Определить сам ключ по сдвигам
            key = self.determine_key(self.loaded_file_text, key_length, alphabet_size)

            # Шаг 3: Расшифровать текст с найденным ключом
            decrypted_text = self.vigener_decrypt(self.loaded_file_text, key, alphabet_size)

            # Окно результатов
            result_window = tk.Toplevel(self.root)
            result_window.title("Результаты взлома")

            tk.Label(result_window, text=f"Найденный ключ: {key}").pack(pady=10)

            # Создаём текстовый виджет для вывода результата
            text_widget = tk.Text(result_window, wrap=tk.WORD, height=20, width=80)
            text_widget.insert(tk.END, decrypted_text)  # Вставляем текст
            text_widget.pack(pady=10)  # Убедитесь, что вызываете pack на объекте text_widget
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")

    def find_key_length(self, text, alphabet_size):
        text = re.sub(r'[^а-яёa-z]', '', text.lower())  # Удаляем все, кроме букв
        max_length = 20  # Ограничение на максимальную длину ключа
        ic_threshold = 0.06 if alphabet_size == 26 else 0.055  # Порог для индекса совпадений
        text_length = len(text)

        for key_length in range(1, max_length + 1):
            segments = [''.join(text[i::key_length]) for i in range(key_length)]
            average_ic = sum(self.calculate_ic(segment, alphabet_size) for segment in segments) / key_length
            if average_ic > ic_threshold:
                return key_length
        return None

    def calculate_ic(self, text, alphabet_size):
        frequencies = Counter(text)
        text_length = len(text)
        if text_length <= 1:
            return 0
        return sum(freq * (freq - 1) for freq in frequencies.values()) / (text_length * (text_length - 1))

    def determine_key(self, text, key_length, alphabet_size):
        text = re.sub(r'[^а-яёa-z]', '', text.lower())
        key = ""
        for i in range(key_length):
            segment = ''.join(text[j] for j in range(i, len(text), key_length))
            shift = self.find_caesar_shift(segment, alphabet_size)
            key += chr(shift + (ord('а') if alphabet_size == 32 else ord('a')))
        return key

    def find_caesar_shift(self, text, alphabet_size):
        language_frequencies = {
            32: [0.0862, 0.0160, 0.0454, 0.0174, 0.0300, 0.0261, 0.0134, 0.0070, 0.0741, 0.0121, 0.0349, 0.0359,
                 0.0497, 0.0670, 0.1097, 0.0282, 0.0004, 0.0473, 0.0547, 0.0635, 0.0262, 0.0015, 0.0034, 0.0186,
                 0.0094, 0.0133, 0.0007, 0.0033, 0.0122, 0.0002, 0.0010, 0.0077],  # Частоты букв русского языка
            26: [0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697, 0.0015, 0.0077, 0.0403,
                 0.0241, 0.0675, 0.0751, 0.0193, 0.0009, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015,
                 0.0197, 0.0007]  # Частоты букв английского языка
        }
        expected_freq = language_frequencies[alphabet_size]

        best_shift = 0
        max_correlation = -math.inf
        for shift in range(alphabet_size):
            shifted_text = ''.join(
                chr((ord(char) - (ord('а') if alphabet_size == 32 else ord('a')) - shift) % alphabet_size +
                    (ord('а') if alphabet_size == 32 else ord('a')))
                for char in text
            )
            actual_freq = [shifted_text.count(chr(i + (ord('а') if alphabet_size == 32 else ord('a')))) / len(text)
                           for i in range(alphabet_size)]
            correlation = sum(f * e for f, e in zip(actual_freq, expected_freq))
            if correlation > max_correlation:
                max_correlation = correlation
                best_shift = shift
        return best_shift


if __name__ == "__main__":
    root = tk.Tk()
    app = VigenerCipherApp(root)
    root.mainloop()
