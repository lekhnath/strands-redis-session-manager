# -*- coding: utf-8 -*-
"""This script shows a simple example of using strands-redis-session-manager."""

import asyncio
import os
import uuid

import redis
from dotenv import load_dotenv
from strands import Agent
from strands.models.bedrock import BedrockModel

from redis_session_manager import RedisSessionManager

load_dotenv()


def get_redis_client() -> redis.Redis:
    return redis.from_url(os.getenv("REDIS_CACHE"))


def get_agent(session_id: str):
    return Agent(
        agent_id="my-agent",
        state={"counter": 0},
        model=BedrockModel(model_id="amazon.nova-micro-v1:0"),
        session_manager=RedisSessionManager(
            session_id=session_id,
            redis_client=get_redis_client(),
            ttl_seconds=60,
        ),
        callback_handler=None,
    )


async def main():
    session_id = str(uuid.uuid4())[:8]

    print("This script demonstrates how to use the strands session manager with Redis.")
    print("Make sure the following are ready before running this example:")
    print("1. Redis server is running.")
    print(
        "2. The Redis connection string is configured in a '.env' file (use '.env-example' as a reference)."
    )
    print("3. AWS credentials are set up for Bedrock models.")
    print("\nNote: A Docker configuration is provided to run Redis locally.")
    print(
        "- Use the 'Makefile' for convenience. Run '$ make dev' to start Redis in a Docker container."
    )
    print(f"Current session: {session_id}")
    print("\nOptions:")
    print("  'exit' - Exit the program")
    print("Ask me anything.")

    # Interactive loop
    while True:
        try:
            user_input = input("\n> ")

            if user_input.lower() == "exit":
                print("\nGoodbye! 👋")
                break

            # Initialize a new agent per new user request mimicing http server like request
            agent = get_agent(session_id=session_id)

            # increment counter from agent state which will also get persisted
            counter = int(agent.state.get("counter") or 0)
            agent.state.set("counter", counter + 1)

            # invoke agent with user input
            response = await agent.invoke_async(user_input)

            # print the response
            print(f"\nResponse: {str(response)}")

        except KeyboardInterrupt:
            print("\n\nExecution interrupted. Exiting...")
            break
        except Exception as e:
            print(f"\nAn error occurred: {str(e)}")
            print("Please try a different request.")


if __name__ == "__main__":
    asyncio.run(main())
