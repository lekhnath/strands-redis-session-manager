# Tests Documentation

## Overview

This project uses `pytest` for testing and `fakeredis` for in-memory Redis emulation, which means **no Redis server is required** to run the tests.

## Test Coverage

Current test coverage: **95%** (35 tests)

The test suite covers:

### Session Operations
- Creating sessions
- Reading sessions (existing and non-existent)
- Deleting sessions (with and without associated data)
- Duplicate session handling

### Agent Operations
- Creating agents within sessions
- Reading agent data
- Updating agent state
- Error handling for non-existent agents

### Message Operations
- Creating messages for agents
- Reading individual messages
- Listing messages (all, with limit, with offset)
- Updating message content
- Sorted set indexing verification

### Multi-Agent Operations
- Creating multi-agent state
- Reading multi-agent data
- Updating multi-agent state
- Proper serialization/deserialization

### TTL (Time-To-Live) Features
- Session expiry with TTL
- Sessions without TTL
- Rolling TTL on write operations
- Touch-on-read functionality

### Error Handling
- Corrupted JSON data
- Non-existent resource operations
- Invalid session/agent/message access

## Running Tests

### Quick Start

```bash
# Install dependencies
make install

# Run all unit tests
make test-unit

# Run all tests
make test

# Run with coverage
make test-cov

# Generate HTML coverage report
make test-cov-html
```

### Direct pytest Commands

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/unit/test_session_manager.py -v

# Run specific test
pytest tests/unit/test_session_manager.py::test_create_session -v

# Run with coverage
pytest tests/ --cov=redis_session_manager --cov-report=term-missing

# Run tests matching a pattern
pytest tests/ -k "session" -v
```

## Test Structure

```
tests/
├── __init__.py
├── README.md (this file)
└── unit/
    ├── __init__.py
    └── test_session_manager.py  # Main test suite
```

## Fixtures

The test suite provides several reusable fixtures:

- `redis_client`: FakeRedis instance for testing
- `redis_manager`: RedisSessionManager instance
- `sample_session`: Sample Session object
- `sample_agent`: Sample SessionAgent object
- `sample_message`: Sample SessionMessage object
- `mock_multi_agent`: Mock multi-agent object

## Adding New Tests

When adding new tests:

1. Follow the existing naming convention: `test_<functionality>`
2. Use descriptive docstrings
3. Group related tests with section comments
4. Use the provided fixtures when possible
5. Ensure tests are independent (no shared state)

Example:

```python
def test_my_new_feature(redis_manager, sample_session):
    """Test my new feature does X."""
    # Setup
    redis_manager.create_session(sample_session)
    
    # Exercise
    result = redis_manager.my_new_feature(sample_session.session_id)
    
    # Verify
    assert result is not None
```

## CI/CD Integration

These tests are designed to run in CI/CD pipelines without external dependencies:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    pip install -e ".[dev]"
    pytest tests/ --cov=redis_session_manager
```

## Test Philosophy

- **No external dependencies**: Uses fakeredis for in-memory testing
- **Fast execution**: All tests run in under 1 second
- **High coverage**: Maintains >90% code coverage
- **Clear assertions**: Each test verifies specific behavior
- **Isolated tests**: No shared state between tests
