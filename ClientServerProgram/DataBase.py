from sqlite3 import IntegrityError
import sqlite3


class UserDatabase:
    def __init__(self, db_name="users.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        self.cursor.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT
            )"""
        )
        self.conn.commit()

    def add_user(self, username, password):
        try:
            self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            self.conn.commit()
            return True
        except IntegrityError:
            return False

    def user_exists(self, username):
        self.cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        return self.cursor.fetchone() is not None

    def get_password(self, username):
        self.cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def get_all_users(self):
        """Метод для получения списка всех пользователей."""
        self.cursor.execute("SELECT username FROM users")
        users = self.cursor.fetchall()
        return [user[0] for user in users]