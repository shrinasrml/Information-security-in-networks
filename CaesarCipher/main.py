import tkinter as tk
from tkinter import filedialog, messagebox
from collections import Counter
import re

class CaesarCipherApp:
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
            allowed_chars = re.compile(r'^[а-яА-Я0-9]*$')
        else:
            allowed_chars = re.compile(r'^[a-zA-Z0-9]*$')
        if not allowed_chars.search(text):
            messagebox.showerror("Ошибка",
                                 f"Текст должен содержать только символы на {'русском' if self.language.get() == 'ru' else 'английском'} языке и цифры.")
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
                  command=lambda: self.decrypt_message(entry_encrypted, entry_key, entry_decrypted)).grid(row=6,
                                                                                                          column=1)

    def open_encryption_decryption_file_window(self):
        # Окно для работы с файлами
        window = tk.Toplevel(self.root)
        window.title("Шифровка и расшифровка текста из файла")

        self.loaded_file_text = ""
        self.encrypted_text = ""

        # Добавляем переключатель для выбора языка
        tk.Label(window, text="Выберите язык:").grid(row=0, column=0)
        tk.Radiobutton(window, text="Русский", variable=self.language, value="ru").grid(row=0, column=1)
        tk.Radiobutton(window, text="Английский", variable=self.language, value="en").grid(row=0, column=2)

        # Кнопки для загрузки, шифрования и сохранения файла
        tk.Button(window, text="Загрузить файл", command=self.load_file).grid(row=1, column=0)
        tk.Button(window, text="Зашифровать файл", command=lambda: self.encrypt_file(window)).grid(row=1, column=1)
        tk.Button(window, text="Сохранить файл", command=self.save_file).grid(row=1, column=2)

        # Поле для ввода ключа
        tk.Label(window, text="Ключ:").grid(row=2, column=0)
        entry_key = tk.Entry(window, width=15)
        self.entry_key_file = entry_key
        self.entry_key_file.grid(row=2, column=1)

    def open_hack_cipher_window(self):
        # Окно для взлома шифра
        window = tk.Toplevel(self.root)
        window.title("Взлом шифра")

        # Кнопка для выбора файла и взлома
        tk.Button(window, text="Выбрать файл", command=self.load_file).grid(row=0, column=0)
        tk.Button(window, text="Взломать шифр", command=self.hack_cipher).grid(row=0, column=1)

    def caesar_shift(self, text, shift, alphabet_size):
        result = []
        text = text.lower().replace('ё', 'е')  # Преобразуем весь текст в нижний регистр
        for char in text:
            if char.isalpha():  # Шифруем только буквы
                if 'а' <= char <= 'я':
                    base = ord('а')
                    offset = 32
                    result.append(chr((ord(char) - base + shift) % offset + base))
                elif 'a' <= char <= 'z':
                    base = ord('a')
                    offset = 26
                    result.append(chr((ord(char) - base + shift) % offset + base))
            elif char.isdigit():  # Шифруем только цифры
                result.append(chr((ord(char) - ord('0') + shift) % 10 + ord('0')))
            else:
                # Добавляем символы без изменений
                result.append(char)
        return ''.join(result)

    def encrypt_message(self, entry_message, entry_key, entry_encrypted):
        try:
            message = entry_message.get().strip().lower()  # Приводим к нижнему регистру
            if not message:
                messagebox.showerror("Ошибка", "Поле исходного сообщения не должно быть пустым")
            if not self.validate_text(message):  # Проверяем на допустимые символы
                return
            key = int(entry_key.get())
            alphabet_size = 32 if self.language.get() == "ru" else 26
            encrypted = self.caesar_shift(message, key, alphabet_size)
            entry_encrypted.delete(0, tk.END)
            entry_encrypted.insert(tk.END, encrypted)
        except ValueError:
            messagebox.showerror("Ошибка", "Ключ должен быть целым числом.")

    def decrypt_message(self, entry_encrypted, entry_key, entry_decrypted):
        try:
            encrypted_message = entry_encrypted.get().strip().lower()  # Приводим к нижнему регистру
            if not self.validate_text(encrypted_message):  # Проверяем на допустимые символы
                return
            key = int(entry_key.get())
            alphabet_size = 32 if self.language.get() == "ru" else 26
            decrypted = self.caesar_shift(encrypted_message, -key, alphabet_size)
            entry_decrypted.delete(0, tk.END)
            entry_decrypted.insert(tk.END, decrypted)
        except ValueError:
            messagebox.showerror("Ошибка", "Ключ должен быть целым числом.")

    def load_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as file:
                self.loaded_file_text = file.read()
            if not self.validate_text(self.loaded_file_text):
                self.loaded_file_text = ""
            else:
                messagebox.showinfo("Файл загружен", "Файл успешно загружен.")

    def encrypt_file(self, window):
        try:
            key = int(self.entry_key_file.get())
            alphabet_size = 32 if re.search('[а-яА-Я]', self.loaded_file_text) else 26
            self.encrypted_text = self.caesar_shift(self.loaded_file_text, key, alphabet_size)
            messagebox.showinfo("Шифрование завершено", "Файл успешно зашифрован.")
        except ValueError:
            messagebox.showerror("Ошибка", "Ключ должен быть целым числом.")

    def save_file(self):
        if self.encrypted_text:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt")
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(self.encrypted_text)
            messagebox.showinfo("Файл сохранён", "Зашифрованный файл успешно сохранён.")
        else:
            messagebox.showwarning("Нет данных", "Нет данных для сохранения.")

    def hack_cipher(self):
        if not self.loaded_file_text:
            messagebox.showwarning("Нет файла", "Пожалуйста, загрузите файл для взлома.")
            return

        freq_analysis_result = self.frequency_analysis(self.loaded_file_text)
        messagebox.showinfo("Взлом завершен",
                            f"Ключ: {freq_analysis_result['key']}\nРасшифрованный текст:\n{freq_analysis_result['text']}")

    def frequency_analysis(self, text):
        # Заменяем ё на е для анализа
        text = text.lower().replace('ё', 'е')

        # Часто встречающиеся буквы для русского и английского языков
        common_letters = ['оеа'] if self.language.get() == "ru" else ['eta']
        alphabet_size = 32 if self.language.get() == "ru" else 26

        # Считаем количество каждой буквы в тексте
        letter_count = Counter(filter(str.isalpha, text))
        most_freq_letter_in_text = letter_count.most_common(1)[0][0]

        likely_key = None
        best_match_score = 0
        best_decrypted_text = text

        # Проходим по списку возможных частотных букв
        for common_letter in common_letters:
            for letter in common_letter:
                # Рассчитываем возможный ключ
                possible_key = (ord(most_freq_letter_in_text) - ord(letter)) % alphabet_size

                # Дешифруем текст с этим ключом
                decrypted_text = self.caesar_shift(text, -possible_key, alphabet_size)

                # Подсчитываем количество совпадений с исходной статистикой
                match_score = sum(1 for char in decrypted_text if char in common_letter)

                # Выбираем расшифровку с наибольшим количеством совпадений
                if match_score > best_match_score:
                    best_match_score = match_score
                    best_decrypted_text = decrypted_text
                    likely_key = possible_key

        return {"key": likely_key, "text": best_decrypted_text}


# Запуск приложения
root = tk.Tk()
app = CaesarCipherApp(root)
root.mainloop()
