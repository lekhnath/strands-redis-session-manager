# strands-redis-session-manager

Redis-based session management for persisting and managing agent sessions in the Strands Agents SDK.

## Description

A community package for Amazon Strands Agents that provides Redis-based session persistence and management. This package allows you to store and retrieve agent conversation history and state using Redis as the backend, enabling stateful conversations across multiple interactions.

## Features

- 🔄 Session persistence with Redis
- 💾 Store and retrieve agent conversation history
- 🚀 Simple integration with Strands Agents SDK
- 🔧 Configurable
- 🐍 Python 3.12+ support

## Requirements

- Python 3.12+
- Strands Agents SDK 1.16.0+
- Redis 7.0.1+

## Installation

```bash
pip install strands-agents strands-redis-session-manager
```

## Quick Start

```python
from redis_session_manager import RedisSessionManager
from strands import Agent

# Initialize Redis session manager
session_manager = RedisSessionManager(
    session_id='<session_id>',
    redis_client=get_redis_client(),
    ttl_seconds=600, # Optional[int]
    ...
)

# Create your agent with session management
agent = Agent(
  agent_id='my-agent',
  model=your_model,
  session_manager=session_manager,
  ...
)

# Use session manager to persist conversations
# (See examples/ directory for detailed usage)
```

## Running Locally

### Prerequisites

1. Clone the repository:
```bash
git clone https://github.com/lekhnath/strands-redis-session-manager.git
cd strands-redis-session-manager
```

2. Set up Python environment (Python 3.12+):
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -e ".[dev]"
# or using uv
uv pip install -e .
```

4. Start Redis (using Docker):
```bash
docker compose -f compose.redis.yml up -d
```

5. Copy environment variables:
```bash
cp .env-example .env
# Edit .env with your configuration
```

## Running Tests

Tests use `fakeredis` for in-memory testing, so no Redis server is required.

Run integration tests:
```bash
make test-integration
# or directly with pytest
pytest tests/integration/ -v
```

Run all tests:
```bash
make test
# or directly with pytest
pytest tests/ -v
```

Run tests with coverage:
```bash
make test-cov
# or directly with pytest
pytest tests/ --cov=redis_session_manager --cov-report=term-missing
```

Run tests with HTML coverage report:
```bash
make test-cov-html
# Opens coverage report in htmlcov/index.html
```

### Additional Make Commands

```bash
make install        # Install dependencies
make lint           # Run linter
make format         # Format code
make help           # Show all available commands
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License.

## Links

- [Strands Agents SDK](https://strandsagents.com/)
- [PyPI Package](https://pypi.org/project/strands-redis-session-manager/)
- [Issue Tracker](https://github.com/lekhnath/strands-redis-session-manager/issues)

## Acknowledgments

Thanks to the Strands Agents team for creating an excellent SDK for building AI agents.
