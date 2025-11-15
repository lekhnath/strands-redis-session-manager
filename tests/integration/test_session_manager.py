"""Unit tests for RedisSessionManager."""

from unittest.mock import Mock

import fakeredis
import pytest
from strands.agent.conversation_manager.null_conversation_manager import (
    NullConversationManager,
)
from strands.types.content import ContentBlock
from strands.types.exceptions import SessionException
from strands.types.session import Session, SessionAgent, SessionMessage, SessionType

from redis_session_manager import RedisSessionManager


@pytest.fixture
def redis_client():
    """Create a fake Redis client for testing."""
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def redis_manager(redis_client):
    """Create RedisSessionManager for testing."""
    return RedisSessionManager(session_id="test", redis_client=redis_client)


@pytest.fixture
def sample_session():
    """Create sample session for testing."""
    return Session(session_id="test-session", session_type=SessionType.AGENT)


@pytest.fixture
def sample_agent():
    """Create sample agent for testing."""
    return SessionAgent(
        agent_id="test-agent",
        state={"key": "value"},
        conversation_manager_state=NullConversationManager().get_state(),
    )


@pytest.fixture
def sample_message():
    """Create sample message for testing."""
    return SessionMessage.from_message(
        message={
            "role": "user",
            "content": [ContentBlock(text="Hello world")],
        },
        index=0,
    )


@pytest.fixture
def mock_multi_agent():
    """Create mock multi-agent for testing."""
    mock = Mock()
    mock.id = "test-multi-agent"
    mock.state = {"key": "value"}
    mock.serialize_state.return_value = {
        "id": "test-multi-agent",
        "state": {"key": "value"},
    }
    return mock


# -------- Session Tests --------


def test_create_session(redis_manager, sample_session):
    """Test creating a session."""
    redis_manager.create_session(sample_session)

    # Verify session exists in Redis
    key = redis_manager._k_session(sample_session.session_id)
    assert redis_manager.redis.exists(key)

    # Verify session can be read back
    result = redis_manager.read_session(sample_session.session_id)
    assert result.session_id == sample_session.session_id
    assert result.session_type == sample_session.session_type


def test_create_duplicate_session(redis_manager, sample_session):
    """Test creating a session that already exists."""
    redis_manager.create_session(sample_session)

    # Attempting to create the same session again should raise an exception
    with pytest.raises(SessionException, match="already exists"):
        redis_manager.create_session(sample_session)


def test_read_session(redis_manager, sample_session):
    """Test reading an existing session."""
    # Create session first
    redis_manager.create_session(sample_session)

    # Read it back
    result = redis_manager.read_session(sample_session.session_id)

    assert result.session_id == sample_session.session_id
    assert result.session_type == sample_session.session_type


def test_read_nonexistent_session(redis_manager):
    """Test reading a session that doesn't exist."""
    result = redis_manager.read_session("nonexistent-session")
    assert result is None


def test_delete_session(redis_manager, sample_session):
    """Test deleting a session."""
    # Create session first
    redis_manager.create_session(sample_session)
    key = redis_manager._k_session(sample_session.session_id)
    assert redis_manager.redis.exists(key)

    # Delete session
    redis_manager.delete_session(sample_session.session_id)

    # Verify deletion
    assert not redis_manager.redis.exists(key)


def test_delete_nonexistent_session(redis_manager):
    """Test deleting a session that doesn't exist."""
    with pytest.raises(SessionException, match="does not exist"):
        redis_manager.delete_session("nonexistent-session")


def test_delete_session_with_agents_and_messages(
    redis_manager, sample_session, sample_agent, sample_message
):
    """Test deleting a session with agents and messages."""
    # Create session, agent, and message
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)
    redis_manager.create_message(
        sample_session.session_id, sample_agent.agent_id, sample_message
    )

    # Verify all keys exist
    session_key = redis_manager._k_session(sample_session.session_id)
    agent_key = redis_manager._k_agent(sample_session.session_id, sample_agent.agent_id)
    message_key = redis_manager._k_message(
        sample_session.session_id, sample_agent.agent_id, sample_message.message_id
    )

    assert redis_manager.redis.exists(session_key)
    assert redis_manager.redis.exists(agent_key)
    assert redis_manager.redis.exists(message_key)

    # Delete session
    redis_manager.delete_session(sample_session.session_id)

    # Verify all keys are deleted
    assert not redis_manager.redis.exists(session_key)
    assert not redis_manager.redis.exists(agent_key)
    assert not redis_manager.redis.exists(message_key)


# -------- Agent Tests --------


def test_create_agent(redis_manager, sample_session, sample_agent):
    """Test creating an agent in a session."""
    # Create session first
    redis_manager.create_session(sample_session)

    # Create agent
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    # Verify agent exists
    key = redis_manager._k_agent(sample_session.session_id, sample_agent.agent_id)
    assert redis_manager.redis.exists(key)

    # Verify agent can be read back
    result = redis_manager.read_agent(sample_session.session_id, sample_agent.agent_id)
    assert result.agent_id == sample_agent.agent_id
    assert result.state == sample_agent.state


def test_create_agent_without_session(redis_manager, sample_agent):
    """Test creating an agent without a session."""
    with pytest.raises(SessionException, match="does not exist"):
        redis_manager.create_agent("nonexistent-session", sample_agent)


def test_read_agent(redis_manager, sample_session, sample_agent):
    """Test reading an agent from a session."""
    # Create session and agent
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    # Read agent
    result = redis_manager.read_agent(sample_session.session_id, sample_agent.agent_id)

    assert result.agent_id == sample_agent.agent_id
    assert result.state == sample_agent.state


def test_read_nonexistent_agent(redis_manager, sample_session):
    """Test reading an agent that doesn't exist."""
    result = redis_manager.read_agent(sample_session.session_id, "nonexistent_agent")
    assert result is None


def test_update_agent(redis_manager, sample_session, sample_agent):
    """Test updating an agent."""
    # Create session and agent
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    # Update agent
    sample_agent.state = {"updated": "value"}
    redis_manager.update_agent(sample_session.session_id, sample_agent)

    # Verify update
    result = redis_manager.read_agent(sample_session.session_id, sample_agent.agent_id)
    assert result.state == {"updated": "value"}


def test_update_nonexistent_agent(redis_manager, sample_session, sample_agent):
    """Test updating an agent that doesn't exist."""
    # Create session
    redis_manager.create_session(sample_session)

    # Update agent
    with pytest.raises(SessionException, match="does not exist"):
        redis_manager.update_agent(sample_session.session_id, sample_agent)


# -------- Message Tests --------


def test_create_message(redis_manager, sample_session, sample_agent, sample_message):
    """Test creating a message for an agent."""
    # Create session and agent
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    # Create message
    redis_manager.create_message(
        sample_session.session_id, sample_agent.agent_id, sample_message
    )

    # Verify message exists
    message_key = redis_manager._k_message(
        sample_session.session_id, sample_agent.agent_id, sample_message.message_id
    )
    assert redis_manager.redis.exists(message_key)

    # Verify message is in the sorted set
    zset_key = redis_manager._k_messages_zset(
        sample_session.session_id, sample_agent.agent_id
    )
    assert redis_manager.redis.zcard(zset_key) == 1


def test_read_message(redis_manager, sample_session, sample_agent, sample_message):
    """Test reading a message."""
    # Create session, agent, and message
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)
    redis_manager.create_message(
        sample_session.session_id, sample_agent.agent_id, sample_message
    )

    # Create multiple messages when reading
    sample_message.message_id = sample_message.message_id + 1
    redis_manager.create_message(
        sample_session.session_id, sample_agent.agent_id, sample_message
    )

    # Read message
    result = redis_manager.read_message(
        sample_session.session_id, sample_agent.agent_id, sample_message.message_id
    )

    assert result.message_id == sample_message.message_id
    assert result.message["role"] == sample_message.message["role"]
    assert result.message["content"] == sample_message.message["content"]


def test_read_messages_with_new_agent(redis_manager, sample_session, sample_agent):
    """Test reading a message with a new agent."""
    # Create session and agent
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    result = redis_manager.read_message(
        sample_session.session_id, sample_agent.agent_id, 999
    )

    assert result is None


def test_read_nonexistent_message(redis_manager, sample_session, sample_agent):
    """Test reading a message that doesn't exist."""
    result = redis_manager.read_message(
        sample_session.session_id, sample_agent.agent_id, 999
    )
    assert result is None


def test_list_messages_all(redis_manager, sample_session, sample_agent):
    """Test listing all messages for an agent."""
    # Create session and agent
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    # Create multiple messages
    messages = []
    for i in range(5):
        message = SessionMessage(
            message={
                "role": "user",
                "content": [ContentBlock(text=f"Message {i}")],
            },
            message_id=i,
        )
        messages.append(message)
        redis_manager.create_message(
            sample_session.session_id, sample_agent.agent_id, message
        )

    # List all messages
    result = redis_manager.list_messages(
        sample_session.session_id, sample_agent.agent_id
    )

    assert len(result) == 5


def test_list_messages_with_limit(redis_manager, sample_session, sample_agent):
    """Test listing messages with limit."""
    # Create session and agent
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    # Create multiple messages
    for i in range(10):
        message = SessionMessage(
            message={
                "role": "user",
                "content": [ContentBlock(text=f"Message {i}")],
            },
            message_id=i,
        )
        redis_manager.create_message(
            sample_session.session_id, sample_agent.agent_id, message
        )

    # List with limit
    result = redis_manager.list_messages(
        sample_session.session_id, sample_agent.agent_id, limit=3
    )

    assert len(result) == 3


def test_list_messages_with_offset(redis_manager, sample_session, sample_agent):
    """Test listing messages with offset."""
    # Create session and agent
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    # Create multiple messages
    for i in range(10):
        message = SessionMessage(
            message={
                "role": "user",
                "content": [ContentBlock(text=f"Message {i}")],
            },
            message_id=i,
        )
        redis_manager.create_message(
            sample_session.session_id, sample_agent.agent_id, message
        )

    # List with offset
    result = redis_manager.list_messages(
        sample_session.session_id, sample_agent.agent_id, offset=5
    )

    assert len(result) == 5


def test_list_messages_with_new_agent(redis_manager, sample_session, sample_agent):
    """Test listing messages with new agent."""
    # Create session and agent
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    result = redis_manager.list_messages(
        sample_session.session_id, sample_agent.agent_id
    )

    assert len(result) == 0


def test_list_messages_nonexistent_agent(redis_manager, sample_session):
    """Test listing messages for nonexistent agent."""
    # Create session
    redis_manager.create_session(sample_session)

    with pytest.raises(SessionException, match="not found"):
        redis_manager.list_messages(sample_session.session_id, "nonexistent-agent")


def test_update_message(redis_manager, sample_session, sample_agent, sample_message):
    """Test updating a message."""
    # Create session, agent, and message
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)
    redis_manager.create_message(
        sample_session.session_id, sample_agent.agent_id, sample_message
    )

    # Update message
    sample_message.message["content"] = [ContentBlock(text="Updated content")]
    redis_manager.update_message(
        sample_session.session_id, sample_agent.agent_id, sample_message
    )

    # Verify update
    result = redis_manager.read_message(
        sample_session.session_id, sample_agent.agent_id, sample_message.message_id
    )
    assert result.message["content"][0]["text"] == "Updated content"


def test_update_nonexistent_message(
    redis_manager, sample_session, sample_agent, sample_message
):
    """Test updating a message that doesn't exist."""
    # Create session and agent
    redis_manager.create_session(sample_session)
    redis_manager.create_agent(sample_session.session_id, sample_agent)

    # Update nonexistent message
    with pytest.raises(SessionException, match="does not exist"):
        redis_manager.update_message(
            sample_session.session_id, sample_agent.agent_id, sample_message
        )


# -------- Multi-Agent Tests --------


def test_create_multi_agent(redis_manager, sample_session, mock_multi_agent):
    """Test creating multi-agent state."""
    redis_manager.create_session(sample_session)
    redis_manager.create_multi_agent(sample_session.session_id, mock_multi_agent)

    # Verify multi-agent exists
    key = redis_manager._k_multi_agent(sample_session.session_id, mock_multi_agent.id)
    assert redis_manager.redis.exists(key)

    # Verify content
    result = redis_manager.read_multi_agent(
        sample_session.session_id, mock_multi_agent.id
    )
    assert result["id"] == mock_multi_agent.id
    assert result["state"] == mock_multi_agent.state


def test_create_multi_agent_without_session(redis_manager, mock_multi_agent):
    """Test creating multi-agent without session."""
    with pytest.raises(SessionException, match="does not exist"):
        redis_manager.create_multi_agent("nonexistent-session", mock_multi_agent)


def test_read_multi_agent(redis_manager, sample_session, mock_multi_agent):
    """Test reading multi-agent state."""
    # Create session and multi-agent
    redis_manager.create_session(sample_session)
    redis_manager.create_multi_agent(sample_session.session_id, mock_multi_agent)

    # Read multi-agent
    result = redis_manager.read_multi_agent(
        sample_session.session_id, mock_multi_agent.id
    )

    assert result["id"] == mock_multi_agent.id
    assert result["state"] == mock_multi_agent.state


def test_read_nonexistent_multi_agent(redis_manager, sample_session):
    """Test reading multi-agent state that doesn't exist."""
    result = redis_manager.read_multi_agent(sample_session.session_id, "nonexistent")
    assert result is None


def test_update_multi_agent(redis_manager, sample_session, mock_multi_agent):
    """Test updating multi-agent state."""
    # Create session and multi-agent
    redis_manager.create_session(sample_session)
    redis_manager.create_multi_agent(sample_session.session_id, mock_multi_agent)

    updated_mock = Mock()
    updated_mock.id = mock_multi_agent.id
    updated_mock.serialize_state.return_value = {
        "id": mock_multi_agent.id,
        "state": {"updated": "value"},
    }
    redis_manager.update_multi_agent(sample_session.session_id, updated_mock)

    # Verify update
    result = redis_manager.read_multi_agent(
        sample_session.session_id, mock_multi_agent.id
    )
    assert result["state"] == {"updated": "value"}


def test_update_nonexistent_multi_agent(redis_manager, sample_session):
    """Test updating multi-agent state that doesn't exist."""
    # Create session
    redis_manager.create_session(sample_session)

    nonexistent_mock = Mock()
    nonexistent_mock.id = "nonexistent"
    with pytest.raises(SessionException, match="does not exist"):
        redis_manager.update_multi_agent(sample_session.session_id, nonexistent_mock)


# -------- Error Handling Tests --------


def test_corrupted_json_in_redis(redis_manager, sample_session):
    """Test handling of corrupted JSON in Redis."""
    # Create session
    redis_manager.create_session(sample_session)

    # Corrupt the session data
    key = redis_manager._k_session(sample_session.session_id)
    redis_manager.redis.set(key, "invalid json content")

    # Should raise SessionException
    with pytest.raises(SessionException, match="Invalid JSON"):
        redis_manager.read_session(sample_session.session_id)


# -------- TTL Tests --------


def test_session_with_ttl(redis_client):
    """Test session with TTL set."""
    manager = RedisSessionManager(
        session_id="test", redis_client=redis_client, ttl_seconds=3600
    )

    session = Session(session_id="test-session", session_type=SessionType.AGENT)
    manager.create_session(session)

    # Verify TTL is set
    key = manager._k_session(session.session_id)
    ttl = redis_client.ttl(key)
    assert ttl > 0
    assert ttl <= 3600


def test_session_without_ttl(redis_client):
    """Test session without TTL."""
    manager = RedisSessionManager(
        session_id="test", redis_client=redis_client, ttl_seconds=None
    )

    session = Session(session_id="test-session", session_type=SessionType.AGENT)
    manager.create_session(session)

    # Verify no TTL is set
    key = manager._k_session(session.session_id)
    ttl = redis_client.ttl(key)
    assert ttl == -1  # -1 means no expiry


def test_rolling_ttl_on_write(redis_client, sample_agent):
    """Test rolling TTL on write operations."""
    manager = RedisSessionManager(
        session_id="test",
        redis_client=redis_client,
        ttl_seconds=3600,
        rolling_ttl=True,
    )

    session = Session(session_id="test-session", session_type=SessionType.AGENT)
    manager.create_session(session)

    key = manager._k_session(session.session_id)

    # Create agent (write operation)
    manager.create_agent(session.session_id, sample_agent)

    # TTL should be refreshed (note: in fakeredis this is difficult to test
    # precisely, but we can verify it's still set)
    new_ttl = redis_client.ttl(key)
    assert new_ttl > 0


def test_touch_on_read(redis_client):
    """Test touch on read operations."""
    manager = RedisSessionManager(
        session_id="test",
        redis_client=redis_client,
        ttl_seconds=3600,
        touch_on_read=True,
    )

    session = Session(session_id="test-session", session_type=SessionType.AGENT)
    manager.create_session(session)

    # Read should touch the session
    manager.read_session(session.session_id)

    # Verify TTL is still set
    key = manager._k_session(session.session_id)
    ttl = redis_client.ttl(key)
    assert ttl > 0
