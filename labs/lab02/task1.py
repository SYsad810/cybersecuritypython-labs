"""Завдання 1: модель користувача, сеансу, аудиту та облікового запису."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE_BYTES = 16
MIN_PASSWORD_LENGTH = 8
SESSION_TIMEOUT_SEC = 900

# Локальна частина: латинська літера + ще 2..63 символи [A-Za-z0-9_],
# далі @ і доменне ім'я з принаймні однією крапкою.
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]{2,63}"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$"
)

ACTION_LOGIN_SUCCESS = "login_success"
ACTION_LOGIN_FAILURE = "login_failure"
ACTION_LOGOUT = "logout"
ACTION_SESSION_TIMEOUT = "session_timeout"


def utc_now() -> datetime:
    """Повернути поточний час UTC з інформацією про часовий пояс."""
    return datetime.now(timezone.utc)


class User:
    """Користувач системи з безпечним зберіганням пароля."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        """Створити користувача; пароль задається окремо set_password()."""
        if not username:
            raise ValueError("Ім'я користувача не може бути порожнім")
        self.username = username
        self.email = email  # перевірка через сеттер властивості
        self.role = role
        self.active = active
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        """Електронна пошта користувача."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Змінити e-mail лише після перевірки формату."""
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError(f"Некоректний e-mail: {value!r}")
        self._email = value

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        """Обчислити PBKDF2-HMAC-SHA256 від пароля з сіллю."""
        return hashlib.pbkdf2_hmac(
            PBKDF2_ALGORITHM,
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        )

    def set_password(self, password: str) -> None:
        """Захешувати пароль з новою випадковою сіллю."""
        if not isinstance(password, str) or len(password) < (
            MIN_PASSWORD_LENGTH
        ):
            raise ValueError(
                f"Пароль має містити щонайменше {MIN_PASSWORD_LENGTH} символів"
            )
        salt = os.urandom(SALT_SIZE_BYTES)
        self.__password_salt = salt
        self.__password_hash = self._derive(password, salt)

    def check_password(self, password: str) -> bool:
        """Перевірити пароль із порівнянням у сталий час."""
        if self.__password_hash is None or self.__password_salt is None:
            return False
        candidate = self._derive(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        """Деактивувати обліковий запис."""
        self.active = False

    def __str__(self) -> str:
        """Повернути опис користувача без пароля та його хешу."""
        status = "active" if self.active else "inactive"
        return (
            f"User(username={self.username!r}, email={self.email!r}, "
            f"role={self.role!r}, status={status})"
        )


class Admin(User):
    """Адміністратор - користувач із набором дозволів (наслідування)."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: Iterable[str] | None = None,
        active: bool = True,
    ) -> None:
        """Створити адміністратора з необов'язковим початковим набором прав."""
        super().__init__(username, email, role="admin", active=active)
        # Нова множина для кожного об'єкта - без змінюваного типового значення
        self.permissions: set[str] = set(permissions or ())

    def grant_permission(self, permission: str) -> None:
        """Надати дозвіл."""
        if not permission:
            raise ValueError("Назва дозволу не може бути порожньою")
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Відкликати дозвіл (якщо його немає - нічого не відбувається)."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевірити наявність дозволу."""
        return permission in self.permissions

    def __str__(self) -> str:
        """Повернути опис адміністратора разом із його правами."""
        perms = ", ".join(sorted(self.permissions)) or "-"
        return f"{super().__str__()} permissions=[{perms}]"


class Session:
    """Сеанс користувача з контролем часу неактивності."""

    def __init__(self, ip: str, login_time: datetime | None = None) -> None:
        """Відкрити сеанс з IP-адреси; час - UTC."""
        self.ip = ip
        self.login_time = login_time or utc_now()
        self.last_activity = self.login_time

    def touch(self) -> None:
        """Оновити час останньої активності."""
        self.last_activity = utc_now()

    def is_active(self, timeout_sec: int) -> bool:
        """Перевірити, чи не минув час неактивності timeout_sec."""
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        idle = utc_now() - self.last_activity
        return idle < timedelta(seconds=timeout_sec)

    def __str__(self) -> str:
        """Повернути короткий опис сеансу."""
        return (
            f"Session(ip={self.ip}, "
            f"login={self.login_time:%Y-%m-%d %H:%M:%S} UTC, "
            f"last={self.last_activity:%H:%M:%S} UTC)"
        )


@dataclass(frozen=True)
class AuditRecord:
    """Незмінний запис журналу аудиту."""

    username: str
    action: str
    timestamp: datetime = field(default_factory=utc_now)


class AuditLog:
    """Журнал подій безпеки (без паролів)."""

    def __init__(self) -> None:
        """Створити порожній журнал."""
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> AuditRecord:
        """Додати запис про дію користувача."""
        record = AuditRecord(username=username, action=action)
        self._records.append(record)
        return record

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        """Записи журналу лише для читання."""
        return tuple(self._records)

    def show_all(self) -> None:
        """Вивести всі записи журналу."""
        for number, rec in enumerate(self._records, start=1):
            print(
                f"{number:>2}. {rec.timestamp:%Y-%m-%d %H:%M:%S} UTC | "
                f"{rec.username:<10} | {rec.action}"
            )

    def __len__(self) -> int:
        """Повернути кількість записів."""
        return len(self._records)


class UserAccount:
    """Обліковий запис: композиція User, Session та AuditLog."""

    # Ключ -> допустимі типи значень для __getitem__/__setitem__
    _ALLOWED_KEYS: dict[str, tuple[type, ...]] = {
        "user": (User,),
        "session": (Session, type(None)),
        "audit_log": (AuditLog,),
    }

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        """Створити обліковий запис; журнал створюється, якщо не переданий."""
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Автентифікувати користувача й відкрити сеанс лише при успіху."""
        ok = (
            username == self.user.username
            and self.user.active
            and self.user.check_password(password)
        )
        if not ok:
            self.audit_log.add_log(username, ACTION_LOGIN_FAILURE)
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, ACTION_LOGIN_SUCCESS)
        return True

    def is_authenticated(self) -> bool:
        """Перевірити, що сеанс існує і не минув SESSION_TIMEOUT_SEC."""
        if self.session is None:
            return False
        if self.session.is_active(SESSION_TIMEOUT_SEC):
            return True
        # Прострочений сеанс не подовжується, а завершується
        self.session = None
        self.audit_log.add_log(self.user.username, ACTION_SESSION_TIMEOUT)
        return False

    def logout(self) -> bool:
        """Завершити сеанс і зафіксувати подію в аудиті."""
        if self.session is None:
            return False
        self.session = None
        self.audit_log.add_log(self.user.username, ACTION_LOGOUT)
        return True

    def __getitem__(self, key: str) -> User | Session | AuditLog | None:
        """Доступ до дозволених складових: account["user"]."""
        if key not in self._ALLOWED_KEYS:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value: object) -> None:
        """Заміна дозволених складових із перевіркою типу."""
        if key not in self._ALLOWED_KEYS:
            raise KeyError(key)
        allowed = self._ALLOWED_KEYS[key]
        if not isinstance(value, allowed):
            names = ", ".join(t.__name__ for t in allowed)
            raise TypeError(
                f"{key!r} очікує {names}, отримано {type(value).__name__}"
            )
        setattr(self, key, value)


def run_demo() -> None:
    """Продемонструвати роботу класів Завдання 1."""
    print("--- 1. Створення користувачів ---")
    user = User("firko", "firko_andrii@lpnu.ua", role="analyst")
    user.set_password("S3cure#Pass2026")
    admin = Admin("sec_admin", "sec_admin@lpnu.ua", ["read_logs"])
    admin.set_password("Adm1n@Lviv2026")
    print(user)
    print(admin)

    print("\n--- 2. Вхід у систему ---")
    account = UserAccount(user)
    for password in ("WrongPass123", "S3cure#Pass2026"):
        ok = account.login("firko", password, "10.0.0.15")
        print(f"login('firko', '********') -> {'SUCCESS' if ok else 'FAIL'}")
    print(f"is_authenticated() -> {account.is_authenticated()}")
    print(f"Сеанс: {account['session']}")

    print("\n--- 3. Зміна e-mail з валідацією ---")
    for new_email in ("1bad@mail", "andrii_firko@student.lpnu.ua"):
        try:
            user.email = new_email
            print(f"OK: email -> {user.email}")
        except ValueError as error:
            print(f"ValueError: {error}")

    print("\n--- 4. Права адміністратора ---")
    admin.grant_permission("manage_users")
    admin.grant_permission("block_ip")
    admin.revoke_permission("read_logs")
    print(admin)
    for perm in ("block_ip", "read_logs"):
        print(f"has_permission({perm!r}) -> {admin.has_permission(perm)}")

    print("\n--- 5. __getitem__ / __setitem__ ---")
    print(f"account['user'] -> {account['user'].username}")
    for key, value in (("password_hash", "x"), ("user", "not a user")):
        try:
            account[key] = value
        except (KeyError, TypeError) as error:
            print(f"account[{key!r}] = ... -> {type(error).__name__}: {error}")

    print("\n--- 6. Завершення сеансу за таймаутом ---")
    # Імітуємо 15+ хвилин неактивності без очікування
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC)
    print(f"is_authenticated() -> {account.is_authenticated()}")
    try:
        Session("10.0.0.1").is_active(0)
    except ValueError as error:
        print(f"is_active(0) -> ValueError: {error}")

    print("\n--- 7. Повторний вхід і вихід ---")
    account.login("firko", "S3cure#Pass2026", "10.0.0.15")
    print(f"logout() -> {account.logout()}")
    print(f"is_authenticated() -> {account.is_authenticated()}")
    user.deactivate()
    ok = account.login("firko", "S3cure#Pass2026", "10.0.0.15")
    print(f"login після deactivate() -> {'SUCCESS' if ok else 'FAIL'}")

    print(f"\n--- 8. Журнал AuditLog ({len(account.audit_log)} записів) ---")
    account.audit_log.show_all()
