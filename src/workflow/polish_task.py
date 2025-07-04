import logging
import json
from copy import deepcopy
from langgraph.types import Command
from typing import Literal
from src.llm.llm import get_llm_by_type
from src.llm.agents import AGENT_LLM_MAP
from src.prompts.template import apply_prompt_template, apply_polish_template
from src.tools.search import tavily_tool
from src.interface.agent import State, Router
from src.interface.serialize_types import AgentBuilder
from src.manager import agent_manager
from src.prompts.template import apply_prompt
from langgraph.prebuilt import create_react_agent
from src.workflow.graph import AgentWorkflow
from langchain_mcp_adapters.client import MultiServerMCPClient
from src.manager.mcp import mcp_client_config
from src.workflow.cache import workflow_cache as cache
from src.interface.agent import Agent

logger = logging.getLogger(__name__)



async def polish_agent(_agent: Agent, part_to_edit: str, instruction=None, tools=None):
    if part_to_edit in ['prompt', 'tool']:
        if part_to_edit == 'prompt':
            messages = apply_polish_template(_agent, instruction)
        else:
            TOOLS_DESCRIPTION_TEMPLATE = """
            - **`{tool_name}`**: {tool_description}
            """
            TOOLS_DESCRIPTION = """
            """
            for tool in tools:
                TOOLS_DESCRIPTION += '\n' + TOOLS_DESCRIPTION_TEMPLATE.format(tool_name=tool["name"],
                                                                              tool_description=tool["description"])
            instruction = f'I have selected a new set of tools:{TOOLS_DESCRIPTION}. Please rewrite the prompt according to the new tool list, and it must include all tools'
            messages = apply_polish_template(_agent, instruction)
        response = (
            get_llm_by_type(AGENT_LLM_MAP["polisher"])
            .with_structured_output(Router)
            .invoke(messages)
        )
        return response
    else:
        raise ValueError(f'The expectation for part_to_edit is prompt or tool,but get {part_to_edit}')

