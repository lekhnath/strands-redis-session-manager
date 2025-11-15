# -*- coding: utf-8 -*-
"""Redis-based session management for persisting and managing agent sessions."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Optional, cast

import redis
from strands.session.repository_session_manager import (
    RepositorySessionManager,
    SessionRepository,
)
from strands.types.exceptions import SessionException
from strands.types.session import Session, SessionAgent, SessionMessage

if TYPE_CHECKING:
    from strands.multiagent.base import MultiAgentBase

DEFAULT_REDIS_NS = "strands:session"

logger = logging.getLogger(__name__)


def _json_load(s: Optional[str]) -> dict[str, Any]:
    """Safe JSON load from a Redis string."""
    if s is None:
        return {}
    try:
        return cast(dict[str, Any], json.loads(s))
    except json.JSONDecodeError as e:
        raise SessionException(f"Invalid JSON in Redis value: {str(e)}") from e


def _json_dump(d: dict[str, Any]) -> str:
    """Stable JSON dump (human-readable, UTF-8)."""
    return json.dumps(d, indent=0, ensure_ascii=False)


class RedisSessionManager(RepositorySessionManager, SessionRepository):
    """
    Redis-backed session manager with optional whole-session TTL.

    Expiry model:
        - If ttl_seconds is set, writes register keys into a per-session registry (ns:<sid>:__keys) and apply EXPIRE.
        - rolling_ttl=True refreshes TTL on writes; touch_on_read refreshes TTL on reads.
        - When TTL elapses, all keys expire → entire conversation disappears.
    """

    def __init__(
        self,
        session_id: str,
        *,
        redis_client: redis.Redis,
        namespace: str = DEFAULT_REDIS_NS,
        ttl_seconds: Optional[int] = None,
        rolling_ttl: bool = True,
        touch_on_read: bool = False,
    ):
        self.namespace = namespace.rstrip(":")
        self.redis = redis_client
        self.ttl_seconds = ttl_seconds
        self.rolling_ttl = bool(rolling_ttl)
        self.touch_on_read = bool(touch_on_read)
        super().__init__(session_id=session_id, session_repository=self)

    # -------- Redis key helpers --------

    def _k_session(self, session_id: str) -> str:
        # Root "session" document; grouped by <sid> for Redis Insight hierarchy.
        return f"{self.namespace}:{session_id}:session"

    def _k_agent(self, session_id: str, agent_id: str) -> str:
        return f"{self.namespace}:{session_id}:agent:{agent_id}"

    def _k_multi_agent(self, session_id: str, multi_agent_id: str) -> str:
        # Single JSON blob per multi-agent state
        return f"{self.namespace}:{session_id}:multi_agent:{multi_agent_id}"

    def _k_messages_zset(self, session_id: str, agent_id: str) -> str:
        return f"{self._k_agent(session_id, agent_id)}:msgs"

    def _k_message(self, session_id: str, agent_id: str, message_id: int) -> str:
        return f"{self._k_agent(session_id, agent_id)}:msg:{message_id}"

    def _k_registry(self, session_id: str) -> str:
        # Tracks all keys in this session for TTL management.
        return f"{self.namespace}:{session_id}:__keys"

    # -------- TTL helpers --------

    def _register_and_expire(self, session_id: str, *keys: str) -> None:
        """
        Add keys to the per-session registry and apply EXPIRE if ttl_seconds is set.
        No-ops quickly when ttl_seconds is None.
        """
        if not keys:
            return
        reg = self._k_registry(session_id)
        pipe = self.redis.pipeline()
        pipe.sadd(reg, *keys)
        if self.ttl_seconds is not None:
            for k in keys:
                pipe.expire(k, self.ttl_seconds)
            pipe.expire(reg, self.ttl_seconds)
        pipe.execute()

    def _touch_session(self, session_id: str) -> None:
        """
        Refresh TTL on all keys listed in the registry (sliding TTL).
        Safe to call when ttl_seconds is None or registry is empty.
        """
        if self.ttl_seconds is None:
            return
        reg = self._k_registry(session_id)
        if not self.redis.exists(reg):
            return
        keys = list(self.redis.smembers(reg))
        if not keys:
            return
        pipe = self.redis.pipeline()
        for k in keys:
            pipe.expire(k, self.ttl_seconds)
        pipe.expire(reg, self.ttl_seconds)
        pipe.execute()

    # -------- Session --------

    def create_session(self, session: "Session", **kwargs: Any) -> "Session":
        """Create a new session root key and set TTL if configured."""
        k = self._k_session(session.session_id)
        created = self.redis.set(k, _json_dump(session.to_dict()), nx=True)
        if not created:
            raise SessionException(f"Session {session.session_id} already exists")
        # Track session root + registry
        self._register_and_expire(
            session.session_id, k, self._k_registry(session.session_id)
        )
        return session

    def read_session(self, session_id: str, **kwargs: Any) -> Optional["Session"]:
        """Read session root (optionally touching TTL on read)."""
        raw = self.redis.get(self._k_session(session_id))
        if raw is None:
            return None
        if self.touch_on_read:
            self._touch_session(session_id)
        return Session.from_dict(_json_load(raw))

    def delete_session(self, session_id: str, **kwargs: Any) -> None:
        """
        Delete the entire session subtree.
        Uses the registry plus a SCAN fallback to catch stragglers.
        """
        root_key = self._k_session(session_id)
        if self.redis.get(root_key) is None:
            raise SessionException(f"Session {session_id} does not exist")

        reg = self._k_registry(session_id)
        keys_to_delete = set()
        if self.redis.exists(reg):
            keys_to_delete.update(self.redis.smembers(reg))

        # Fallback: match everything under ns:<sid>:*
        pattern = f"{self.namespace}:{session_id}:*"
        for key in self.redis.scan_iter(pattern):
            keys_to_delete.add(key)

        if keys_to_delete:
            self.redis.delete(*list(keys_to_delete))

    # -------- Agent --------

    def create_agent(
        self, session_id: str, session_agent: "SessionAgent", **kwargs: Any
    ) -> None:
        """Create or overwrite an agent record under a session."""
        if self.redis.get(self._k_session(session_id)) is None:
            raise SessionException(f"Session {session_id} does not exist")

        k_agent = self._k_agent(session_id, session_agent.agent_id)
        self.redis.set(k_agent, _json_dump(session_agent.to_dict()))
        self._register_and_expire(session_id, k_agent)

        if self.rolling_ttl:
            self._touch_session(session_id)

    def read_agent(
        self, session_id: str, agent_id: str, **kwargs: Any
    ) -> Optional["SessionAgent"]:
        """Read agent data (optionally touching TTL on read)."""
        raw = self.redis.get(self._k_agent(session_id, agent_id))
        if raw is None:
            return None
        if self.touch_on_read:
            self._touch_session(session_id)
        return SessionAgent.from_dict(_json_load(raw))

    def update_agent(
        self, session_id: str, session_agent: "SessionAgent", **kwargs: Any
    ) -> None:
        """Update an existing agent while preserving created_at."""
        prev = self.read_agent(session_id=session_id, agent_id=session_agent.agent_id)
        if prev is None:
            raise SessionException(
                f"Agent {session_agent.agent_id} in session {session_id} does not exist"
            )
        session_agent.created_at = prev.created_at
        k_agent = self._k_agent(session_id, session_agent.agent_id)
        self.redis.set(k_agent, _json_dump(session_agent.to_dict()))
        self._register_and_expire(session_id, k_agent)

        if self.rolling_ttl:
            self._touch_session(session_id)

    # -------- Message --------

    def create_message(
        self,
        session_id: str,
        agent_id: str,
        session_message: "SessionMessage",
        **kwargs: Any,
    ) -> None:
        """
        Store a message and index it in the agent-level ZSET.
        ZADD creates the ZSET if it doesn't exist.
        """
        k_msg = self._k_message(session_id, agent_id, session_message.message_id)
        k_z = self._k_messages_zset(session_id, agent_id)

        payload = _json_dump(session_message.to_dict())
        pipe = self.redis.pipeline()
        pipe.set(k_msg, payload)
        pipe.zadd(
            k_z, {str(session_message.message_id): float(session_message.message_id)}
        )
        pipe.execute()

        self._register_and_expire(session_id, k_msg, k_z)

        if self.rolling_ttl:
            self._touch_session(session_id)

    def read_message(
        self, session_id: str, agent_id: str, message_id: int, **kwargs: Any
    ) -> Optional["SessionMessage"]:
        """Read a single message (optionally touching TTL on read)."""
        raw = self.redis.get(self._k_message(session_id, agent_id, message_id))
        if raw is None:
            return None
        if self.touch_on_read:
            self._touch_session(session_id)
        return SessionMessage.from_dict(_json_load(raw))

    def update_message(
        self,
        session_id: str,
        agent_id: str,
        session_message: "SessionMessage",
        **kwargs: Any,
    ) -> None:
        """Update an existing message while preserving created_at and keeping the index in sync."""
        prev = self.read_message(
            session_id=session_id,
            agent_id=agent_id,
            message_id=session_message.message_id,
        )
        if prev is None:
            raise SessionException(
                f"Message {session_message.message_id} does not exist"
            )
        session_message.created_at = prev.created_at

        k_msg = self._k_message(session_id, agent_id, session_message.message_id)
        self.redis.set(k_msg, _json_dump(session_message.to_dict()))
        self.redis.zadd(
            self._k_messages_zset(session_id, agent_id),
            {str(session_message.message_id): float(session_message.message_id)},
        )

        self._register_and_expire(session_id, k_msg)

        if self.rolling_ttl:
            self._touch_session(session_id)

    def list_messages(
        self,
        session_id: str,
        agent_id: str,
        limit: Optional[int] = None,
        offset: int = 0,
        **kwargs: Any,
    ) -> list["SessionMessage"]:
        """
        List messages in ascending message_id order with pagination.
        """
        if not self.redis.exists(self._k_agent(session_id, agent_id)):
            raise SessionException(
                f"Agent {agent_id} not found in session {session_id}"
            )

        k_z = self._k_messages_zset(session_id, agent_id)
        if self.redis.zcard(k_z) == 0:
            if self.touch_on_read:
                self._touch_session(session_id)
            return []

        start = offset
        end = -1 if limit is None else offset + limit - 1
        msg_ids = self.redis.zrange(k_z, start, end)

        pipe = self.redis.pipeline()
        for mid in msg_ids:
            pipe.get(self._k_message(session_id, agent_id, int(mid)))
        raws = pipe.execute()

        out: list[SessionMessage] = []
        for raw in raws:
            if raw is None:
                continue
            out.append(SessionMessage.from_dict(_json_load(raw)))

        if self.touch_on_read:
            self._touch_session(session_id)

        return out

    # -------- Multi-agent --------

    def create_multi_agent(
        self,
        session_id: str,
        multi_agent: "MultiAgentBase",
        **kwargs: Any,
    ) -> None:
        """
        Create a new multi-agent state in the session.
        """
        # Ensure session exists
        if self.redis.get(self._k_session(session_id)) is None:
            raise SessionException(f"Session {session_id} does not exist")

        k_ma = self._k_multi_agent(session_id, multi_agent.id)
        state = multi_agent.serialize_state()
        self.redis.set(k_ma, _json_dump(state))

        # TTL management
        self._register_and_expire(session_id, k_ma)
        if self.rolling_ttl:
            self._touch_session(session_id)

    def read_multi_agent(
        self,
        session_id: str,
        multi_agent_id: str,
        **kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        """
        Read multi-agent state from Redis.
        """
        k_ma = self._k_multi_agent(session_id, multi_agent_id)
        raw = self.redis.get(k_ma)
        if raw is None:
            return None

        if self.touch_on_read:
            self._touch_session(session_id)

        return _json_load(raw)

    def update_multi_agent(
        self,
        session_id: str,
        multi_agent: "MultiAgentBase",
        **kwargs: Any,
    ) -> None:
        """
        Update existing multi-agent state.

        - Raises SessionException if the state does not exist.
        """
        prev = self.read_multi_agent(
            session_id=session_id, multi_agent_id=multi_agent.id
        )
        if prev is None:
            raise SessionException(
                f"MultiAgent state {multi_agent.id} in session {session_id} does not exist"
            )

        k_ma = self._k_multi_agent(session_id, multi_agent.id)
        state = multi_agent.serialize_state()
        self.redis.set(k_ma, _json_dump(state))

        self._register_and_expire(session_id, k_ma)
        if self.rolling_ttl:
            self._touch_session(session_id)
