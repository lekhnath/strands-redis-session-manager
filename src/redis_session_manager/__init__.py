# -*- coding: utf-8 -*-

"""
Redis-based session management for persisting and managing agent sessions in the Strands Agents SDK.
"""

from .session_manager import RedisSessionManager

__version__ = "0.1.0"
__all__ = ["RedisSessionManager"]
