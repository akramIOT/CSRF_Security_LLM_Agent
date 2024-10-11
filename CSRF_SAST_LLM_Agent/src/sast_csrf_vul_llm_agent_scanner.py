# -*- coding: utf-8 -*-
"""
Created on Tuesday Oct 1 13:23:39 2024
OWASP- SAST 10  , #CSRF Security Threat Vulnerability Scanner with an LLM Agent based  Workflow - written with lanngraph Framework which can be deployed in AWS Cloud
@author: Akram Sheriff
"""

import os
import operator
import functools
from typing import Annotated, Sequence, TypedDict, Literal
import ast  ## AST  is used  many  SAST  Tools  for  Security  Threat  Code  Analysis

from langchain_core.messages import BaseMessage, HumanMessage, ToolMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import AzureChatOpenAI
from langchain_community.tools.tavily_search import TavilySearchResults
from langgraph.graph import END, StateGraph, START
from langgraph.prebuilt import ToolNode

# Set environment variables
os.environ['TAVILY_API_KEY'] = "<>"  # Add your Tavily API key here


# Define the object that is passed between each node in the graph
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    sender: str


class CSRFVulnerabilityDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_FunctionDef(self, node):
        # Check if this function is a route handler
        if any(isinstance(decorator, ast.Call) and decorator.func.id == 'route' for decorator in node.decorator_list):
            self.check_csrf_protection(node)
        self.generic_visit(node)

    def check_csrf_protection(self, node):
        # Check for CSRF token generation and validation
        csrf_token_generated = False
        csrf_token_validated = False

        for n in ast.walk(node):
            if isinstance(n, ast.Assign):
                if isinstance(n.targets[0], ast.Subscript) and isinstance(n.value, ast.Call):
                    if n.value.func.id == 'get_random_token':
                        csrf_token_generated = True

            if isinstance(n, ast.If):
                if isinstance(n.test, ast.Compare):
                    if isinstance(n.test.left, ast.Subscript) and isinstance(n.test.comparators[0], ast.Call):
                        if n.test.comparators[0].func.id == 'validate_token':
                            csrf_token_validated = True

        if csrf_token_generated and not csrf_token_validated:
            self.vulnerabilities.append(f"CSRF token generated but not validated in function {node.name}")
        elif not csrf_token_generated and not csrf_token_validated:
            self.vulnerabilities.append(f"No CSRF protection detected in function {node.name}")

    def report(self):
        if not self.vulnerabilities:
            return "No CSRF vulnerabilities detected."
        else:
            report = "Potential CSRF vulnerabilities detected:\n"
            for vuln in self.vulnerabilities:
                report += f" - {vuln}\n"
            return report


def analyze_code_for_csrf_vulnerabilities(code: str) -> str:
    tree = ast.parse(code)
    detector = CSRFVulnerabilityDetector()
    detector.visit(tree)
    return detector.report()


def create_agent(llm, tools, system_message: str):
    """
    Creates an AI agent using the provided LLM and tools.
    Args:
        llm: The language model instance.
        tools: List of tools that the agent can use.
        system_message: Message template for the agent's system instructions.

    Returns:
        An agent with a prompt template and bound tools.
    """
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a helpful AI assistant, collaborating with other assistants."
                " Use the provided tools to progress towards answering the question."
                " If you are unable to fully answer, that's OK, another assistant with different tools "
                " will help where you left off. Execute what you can to make progress."
                " If you or any of the other assistants have the final answer or deliverable,"
                " prefix your response with FINAL ANSWER so the team knows to stop."
                " You have access to the following tools: {tool_names}.\n{system_message}",
            ),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )
    prompt = prompt.partial(system_message=system_message)
    prompt = prompt.partial(tool_names=", ".join([tool.name for tool in tools]))
    return prompt | llm.bind_tools(tools)


def agent_node(state, agent, name):
    """
    Invokes the agent and updates the global state with the agent's result.
    Args:
        state: Current state of the workflow.
        agent: The agent instance to invoke.
        name: Name of the agent invoking the action.
    Returns:
        Updated state with the agent's message.
    """
    result = agent.invoke(state)

    # Convert the result into a message format suitable to append to the global state
    if not isinstance(result, ToolMessage):
        result = AIMessage(**result.dict(exclude={"type", "name"}), name=name)

    return {
        "messages": [result],
        "sender": name,
    }


def router(state) -> Literal["call_tool", "__end__", "continue"]:
    """
    Route the workflow based on the state of messages.
    Args:
        state: Current state with messages.
    Returns:
        A route decision ("call_tool", "__end__", or "continue").
    """
    messages = state["messages"]
    last_message = messages[-1]

    if last_message.tool_calls:
        return "call_tool"
    if "FINAL ANSWER" in last_message.content:
        return "__end__"

    return "continue"


def setup_workflow():
    """
    Sets up the state graph workflow with agents and tools.

    Returns:
        A compiled graph for workflow execution.
    """
    tavily_tool = TavilySearchResults(max_results=5)

    # Initialize the LLM
    llm = AzureChatOpenAI(
        azure_endpoint=“ < “ >,
    api_key =“ < > ”,
    api_version = "2024-02-01",
    azure_deployment = "GPT_4O"
    )

    # Create the research agent
    research_agent = create_agent(
        llm,
        [tavily_tool],
        system_message="You should provide accurate data."
    )

    # Create the research node
    research_node = functools.partial(agent_node, agent=research_agent, name="Researcher")

    # Initialize the workflow graph
    workflow = StateGraph(AgentState)
    tool_node = ToolNode([tavily_tool])

    # Add nodes and conditional edges to the workflow
    workflow.add_node("Researcher", research_node)
    workflow.add_node("call_tool", tool_node)
    workflow.add_conditional_edges(
        "Researcher",
        router,
        {"continue": "Researcher", "call_tool": "call_tool", "__end__": END},
    )
    workflow.add_conditional_edges(
        "call_tool",
        lambda state: state["sender"],  # Route back to the original agent invoking the tool
        {
            "Researcher": "Researcher",
        },
    )
    workflow.add_edge(START, "Researcher")

    # Compile the workflow
    return workflow.compile()


def run_workflow():
    """
    Runs the workflow graph and streams events for a sample message.
    """
    graph = setup_workflow()

    print("Workflow graph initialized.")

    # Stream events from the graph
    events = graph.stream(
        {
            "messages": [
                HumanMessage(
                    content="Analyze this code for CSRF vulnerabilities:\n@login.route('/login', methods=['POST'])\ndef login():\n    username = request.form.get('username')\n    password = request.form.get('password')\n\n    if validate_credentials(username, password):\n        session['anti_crf_token'] = get_random_token()\n        # ...")
            ]
        },
        {"recursion_limit": 150}
    )

    # Print streamed events
    for event in events:
        print(event)
        print("----")


def lambda_handler(event, context):
    """
    AWS Lambda handler to trigger the workflow execution - To be changed as per additional  Rules or Business Logic for Vulnerability scanning.
    """
    run_workflow()


# Main Driver Code to Invoke the  CSRF  Security  Threat  analysis  Agent  at  Runtime , Example usage to Trigger AWS  Lambda event  handler  which could be #part of an  AWS  Step Function Workflow.
if __name__ == "__main__":
    lambda_handler(event, context)




