import os
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

with open("prompts/responder.txt") as f:
    PROMPT = f.read()

def build_responder(openai_client):
    return Agent(
        name="Responder",
        instructions=PROMPT,
        model=OpenAIChatCompletionsModel(
            model=os.environ["CAI_MODEL"],
            openai_client=openai_client,
        ),
        tools=[]
    )
