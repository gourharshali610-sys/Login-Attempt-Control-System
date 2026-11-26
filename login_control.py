#!/usr/bin/env python3
"""
Login Attempt Control System
----------------------------
A login system that limits repeated wrong-password attempts.
After MAX_ATTEMPTS consecutive failures the account is locked for a while.
Each repeated lockout is longer than the last (escalating penalty).

Run:
    python login_control.py          # interactive menu
    python login_control.py --demo   # automatic walkthrough (simulated clock)

Standard library only.
"""

import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional

# ------------------------------ Settings -----------------------------------
MAX_ATTEMPTS = 3            # failures allowed before lockout
BASE_LOCKOUT_SECONDS = 30   # first lockout length
MAX_LOCKOUT_SECONDS = 600   # cap for escalating lockouts (10 minutes)
MIN_PASSWORD_LEN = 8
DATA_FILE = "users.json"
LOG_FILE = "login_audit.log"

GENERIC_FAIL = "Invalid username or password."


# ------------------------------ Result type --------------------------------
@dataclass
class LoginResult:
    status: str                      # "SUCCESS", "FAILED", or "LOCKED"
    message: str
    attempts_left: Optional[int] = None
    retry_after: int = 0             # seconds until another try is allowed


# ------------------------------ Core system --------------------------------
class LoginSystem:
    def __init__(self, data_file: str = DATA_FILE, log_file: str = LOG_FILE,
                 max_attempts: int = MAX_ATTEMPTS,
                 base_lockout: int = BASE_LOCKOUT_SECONDS,
                 clock: Callable[[], float] = time.time):
        self.data_file = data_file
        self.log_file = log_file
        self.max_attempts = max_attempts
        self.base_lockout = base_lockout
        self.clock = clock          # injectable so tests can fake time
        self.users, self.attempts = {}, {}
        self._load()

    # ---- persistence ----
    def _load(self) -> None:
        if os.path.exists(self.data_file):
            with open(self.data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.users = data.get("users", {})
            self.attempts = data.get("attempts", {})

    def _save(self) -> None:
        tmp = self.data_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"users": self.users, "attempts": self.attempts}, f, indent=2)
        os.replace(tmp, self.data_file)

    def _log(self, event: str, username: str) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.clock()))
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"{stamp} | {event:<14} | {username}\n")

    # ---- password hashing ----
    @staticmethod
    def _hash(password: str, salt: bytes) -> str:
        return hashlib.scrypt(password.encode(), salt=salt,
                              n=2 ** 14, r=8, p=1).hex()

    # ---- registration ----
    def register(self, username: str, password: str) -> LoginResult:
        username = username.strip().lower()
        if not username or not username.isalnum():
            return LoginResult("FAILED", "Username must be letters/numbers only.")
        if len(password) < MIN_PASSWORD_LEN:
            return LoginResult(
                "FAILED", f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        if username in self.users:
            return LoginResult("FAILED", "That username is taken.")
        salt = secrets.token_bytes(16)
        self.users[username] = {"salt": salt.hex(), "hash": self._hash(password, salt)}
        self._save()
        self._log("REGISTERED", username)
        return LoginResult("SUCCESS", "Account created.")

    # ---- login with attempt control ----
    def _state(self, username: str) -> dict:
        # Tracked per username even if the account doesn't exist, so lockout
        # behaviour can't be used to discover which usernames are real.
        return self.attempts.setdefault(
            username, {"failed": 0, "locked_until": 0.0, "lockouts": 0})

    def login(self, username: str, password: str) -> LoginResult:
        username = username.strip().lower()
        state = self._state(username)
        now = self.clock()

        # 1. Already locked? Reject WITHOUT checking the password.
        if state["locked_until"] > now:
            wait = int(state["locked_until"] - now) + 1
            self._log("BLOCKED", username)
            return LoginResult("LOCKED",
                               f"Account temporarily locked. Try again in {wait}s.",
                               attempts_left=0, retry_after=wait)

        # 2. Verify password (always do the hash work, even for unknown users,
        #    so response time doesn't reveal whether the username exists).
        user = self.users.get(username)
        salt = bytes.fromhex(user["salt"]) if user else b"\x00" * 16
        candidate = self._hash(password, salt)
        ok = bool(user) and hmac.compare_digest(candidate, user["hash"])

        # 3. Success: reset the failure counter.
        if ok:
            state.update(failed=0, locked_until=0.0, lockouts=0)
            self._save()
            self._log("LOGIN_OK", username)
            return LoginResult("SUCCESS", f"Welcome, {username}!")

        # 4. Failure: count it, lock if the limit is reached.
        state["failed"] += 1
        self._log("LOGIN_FAILED", username)
        if state["failed"] >= self.max_attempts:
            state["lockouts"] += 1
            duration = min(self.base_lockout * 2 ** (state["lockouts"] - 1),
                           MAX_LOCKOUT_SECONDS)
            state["locked_until"] = now + duration
            state["failed"] = 0
            self._save()
            self._log("LOCKED_OUT", username)
            return LoginResult(
                "LOCKED",
                f"Too many failed attempts. Account locked for {duration}s.",
                attempts_left=0, retry_after=duration)

        self._save()
        left = self.max_attempts - state["failed"]
        return LoginResult("FAILED", f"{GENERIC_FAIL} {left} attempt(s) left.",
                           attempts_left=left)


# ------------------------------ Interactive CLI ----------------------------
def interactive() -> None:
    system = LoginSystem()
    print("=== Login Attempt Control System ===")
    print(f"Rule: {MAX_ATTEMPTS} wrong passwords -> locked "
          f"{BASE_LOCKOUT_SECONDS}s (longer each repeat).\n")
    while True:
        choice = input("[1] Register  [2] Login  [3] Quit > ").strip()
        if choice == "1":
            user = input("New username: ")
            pw = getpass.getpass("New password: ")
            print(" ", system.register(user, pw).message, "\n")
        elif choice == "2":
            user = input("Username: ")
            pw = getpass.getpass("Password: ")
            result = system.login(user, pw)
            print(f"  [{result.status}] {result.message}\n")
        elif choice == "3":
            print("Goodbye!")
            break


# ------------------------------ Demo (fake clock) --------------------------
class FakeClock:
    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def demo() -> None:
    import tempfile
    tmp = tempfile.mkdtemp()
    clock = FakeClock()
    s = LoginSystem(os.path.join(tmp, "u.json"), os.path.join(tmp, "a.log"),
                    clock=clock)

    def show(label, r):
        print(f"  {label:<34} -> [{r.status}] {r.message}")

    print("Demo using a simulated clock (no real waiting)\n")
    s.register("alice", "CorrectHorse9!")

    print("1) Wrong passwords until lockout:")
    for i in range(1, 4):
        show(f"Wrong password #{i}", s.login("alice", "guess" + str(i)))

    print("\n2) Even the CORRECT password is refused while locked:")
    show("Correct password during lockout", s.login("alice", "CorrectHorse9!"))

    print("\n3) After the lockout expires, access is possible again:")
    clock.advance(31)
    show("Correct password after 31s", s.login("alice", "CorrectHorse9!"))

    print("\n4) Repeat offender gets a longer lockout (escalation):")
    for i in range(3):
        s.login("alice", "bad")
    clock.advance(31)
    for i in range(2):
        s.login("alice", "bad")
    show("Second lockout triggered", s.login("alice", "bad"))
    clock.advance(31)
    show("Still locked after 31s", s.login("alice", "CorrectHorse9!"))
    clock.advance(40)
    show("Allowed after 71s", s.login("alice", "CorrectHorse9!"))

    print("\n5) Unknown usernames behave identically (no user enumeration):")
    for i in range(1, 4):
        show(f"Unknown user attempt #{i}", s.login("ghost", "whatever"))

    print("\nAudit log:")
    with open(os.path.join(tmp, "a.log"), encoding="utf-8") as f:
        for line in f.read().splitlines()[:8]:
            print("  " + line)
    print("  ...")


if __name__ == "__main__":
    try:
        demo() if "--demo" in sys.argv else interactive()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye!")
