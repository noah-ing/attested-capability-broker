"""SQLite challenge consumption and at-most-once credential redemption."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .errors import DecisionError, Reason


@dataclass(frozen=True)
class ResourceChallengeRecord:
    token_hash: str
    credential_id: str
    method: str
    arguments_digest: str
    record_id: str
    audience: str
    expires_at: int
    consumed_at: int | None


@dataclass(frozen=True)
class CredentialSpendResult:
    first_spend: bool
    committed_at: int
    challenge_expires_at: int


class SQLiteStore:
    """One-file store; each operation uses its own concurrency-safe connection."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS broker_challenges (
                    token_hash TEXT PRIMARY KEY,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS resource_challenges (
                    token_hash TEXT PRIMARY KEY,
                    credential_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    arguments_digest TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    audience TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS credential_redemptions (
                    credential_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    redeemed_at INTEGER NOT NULL
                );
                """
            )

    def store_broker_challenge(self, *, token_hash: str, issued_at: int, expires_at: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO broker_challenges(token_hash, issued_at, expires_at) VALUES (?, ?, ?)",
                (token_hash, issued_at, expires_at),
            )

    def consume_broker_challenge(self, *, token_hash: str, clock: Callable[[], int]) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            locked_now = clock()
            row = connection.execute(
                "SELECT expires_at, consumed_at FROM broker_challenges WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                raise DecisionError(Reason.CHALLENGE_INVALID, "broker challenge was not issued")
            if row["consumed_at"] is not None:
                raise DecisionError(Reason.CHALLENGE_CONSUMED, "broker challenge was consumed")
            if locked_now >= int(row["expires_at"]):
                raise DecisionError(Reason.CHALLENGE_STALE, "broker challenge expired")
            updated = connection.execute(
                "UPDATE broker_challenges SET consumed_at = ? "
                "WHERE token_hash = ? AND consumed_at IS NULL",
                (locked_now, token_hash),
            )
            if updated.rowcount != 1:
                raise DecisionError(Reason.CHALLENGE_CONSUMED, "broker challenge lost a race")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def store_resource_challenge(
        self,
        *,
        token_hash: str,
        credential_id: str,
        method: str,
        arguments_digest: str,
        record_id: str,
        audience: str,
        issued_at: int,
        expires_at: int,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO resource_challenges(
                    token_hash, credential_id, method, arguments_digest,
                    record_id, audience, issued_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_hash,
                    credential_id,
                    method,
                    arguments_digest,
                    record_id,
                    audience,
                    issued_at,
                    expires_at,
                ),
            )

    def get_resource_challenge(self, token_hash: str) -> ResourceChallengeRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM resource_challenges WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        if row is None:
            return None
        return ResourceChallengeRecord(
            token_hash=str(row["token_hash"]),
            credential_id=str(row["credential_id"]),
            method=str(row["method"]),
            arguments_digest=str(row["arguments_digest"]),
            record_id=str(row["record_id"]),
            audience=str(row["audience"]),
            expires_at=int(row["expires_at"]),
            consumed_at=None if row["consumed_at"] is None else int(row["consumed_at"]),
        )

    def consume_challenge_and_spend_credential(
        self,
        *,
        token_hash: str,
        credential_id: str,
        method: str,
        arguments_digest: str,
        record_id: str,
        audience: str,
        credential_not_before: int,
        credential_not_after: int,
        clock: Callable[[], int],
    ) -> CredentialSpendResult:
        """Consume the challenge and try to spend the credential in one transaction.

        The clock is read after acquiring the SQLite write lock. A non-first
        spend still consumes this fresh challenge, but never invokes a handler.
        """

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            locked_now = clock()
            row = connection.execute(
                "SELECT * FROM resource_challenges WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if row is None:
                raise DecisionError(Reason.CHALLENGE_INVALID, "resource challenge was not issued")
            if row["consumed_at"] is not None:
                raise DecisionError(Reason.CHALLENGE_CONSUMED, "resource challenge was consumed")
            challenge_expires_at = int(row["expires_at"])
            if locked_now >= challenge_expires_at:
                raise DecisionError(Reason.CHALLENGE_STALE, "resource challenge expired")
            if locked_now < credential_not_before or locked_now > credential_not_after:
                raise DecisionError(
                    Reason.CREDENTIAL_EXPIRED,
                    "credential expired while waiting for the SQLite write lock",
                )
            expected = (
                credential_id,
                method,
                arguments_digest,
                record_id,
                audience,
            )
            actual = (
                str(row["credential_id"]),
                str(row["method"]),
                str(row["arguments_digest"]),
                str(row["record_id"]),
                str(row["audience"]),
            )
            if actual != expected:
                raise DecisionError(
                    Reason.HOLDER_PROOF_INVALID, "resource challenge context does not match"
                )

            inserted = connection.execute(
                "INSERT OR IGNORE INTO credential_redemptions("
                "credential_id, token_hash, record_id, redeemed_at) VALUES (?, ?, ?, ?)",
                (credential_id, token_hash, record_id, locked_now),
            )
            updated = connection.execute(
                "UPDATE resource_challenges SET consumed_at = ? "
                "WHERE token_hash = ? AND consumed_at IS NULL",
                (locked_now, token_hash),
            )
            if updated.rowcount != 1:
                raise DecisionError(Reason.CHALLENGE_CONSUMED, "resource challenge lost a race")
            connection.commit()
            return CredentialSpendResult(
                first_spend=inserted.rowcount == 1,
                committed_at=locked_now,
                challenge_expires_at=challenge_expires_at,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def redemption_count(self, credential_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM credential_redemptions WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
        return int(row["count"])
