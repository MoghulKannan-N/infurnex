import os
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

CHAT_PROMPT = """
You are a helpful Linux AI assistant.

RULES:
- Do NOT run system commands
- Do NOT guess system state
- Answer general questions conversationally
"""

def build_chat(openai_client):
    return Agent(
        name="Chat",
        instructions=CHAT_PROMPT,
        model=OpenAIChatCompletionsModel(
            model=os.environ["CAI_MODEL"],
            openai_client=openai_client,
        ),
        tools=[]
    )
