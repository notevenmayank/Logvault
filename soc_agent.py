"""
Sentinel Vault — SOC Investigator Agent (Pillar 2, "Hermes")

A small command-line AI agent that plays the role of a SOC (Security
Operations Center) analyst. You ask it a question in plain English
("is anything tampered right now?", "what happened in window 3?"),
and it decides on its own which MCP tool(s) to call (verify_integrity,
get_alerts, inspect_ledger, analyze_incident), reads the results, and
answers you — exactly like a real investigator would pull up a system
and look something up before answering.

This never invents a status: every fact it uses comes from a tool call
to mcp_server.py, which in turn comes from the same deterministic
verification_core.py logic the dashboard uses. The AI only decides
*which tool to call* and *how to phrase the answer* — never *what the
tamper status is*.

Run with:  python soc_agent.py
(ollama must be running, with the qwen2.5:3b model pulled)
"""
import asyncio
import json
import requests
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import ollama_explainer

OLLAMA_URL = "http://127.0.0.1:11434"
MODEL_NAME = ollama_explainer.MODEL_NAME

SYSTEM_PROMPT = (
    "You are the SOC (Security Operations Center) investigator for Sentinel Vault, "
    "a tamper-proof security log system. You have tools to check the vault's real "
    "status. ALWAYS call a tool before answering any question about the vault's "
    "state, alerts, or specific windows — never guess or make up a status. "
    "Once you have the tool result, answer the user's question in 1-3 plain, "
    "factual sentences. If a question is unrelated to the vault, just answer normally."
)


def mcp_tools_to_ollama_format(tools):
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.input_schema,
            },
        }
        for t in tools
    ]


def call_ollama(messages, tools=None):
    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "stream": False,
    }
    if tools:
        payload["tools"] = tools
    resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=60)
    resp.raise_for_status()
    return resp.json()["message"]


def extract_tool_result_text(result):
    if result.structured_content is not None:
        return json.dumps(result.structured_content)
    if result.content:
        return "\n".join(c.text for c in result.content if hasattr(c, "text"))
    return "(no result)"


async def run_agent():
    params = StdioServerParameters(command="python", args=["mcp_server.py"])

    print("Connecting to Sentinel Vault MCP server...")
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            mcp_tools = (await session.list_tools()).tools
            ollama_tools = mcp_tools_to_ollama_format(mcp_tools)
            print(f"Connected. {len(mcp_tools)} tool(s) available: {', '.join(t.name for t in mcp_tools)}")
            print("Ask a question about the vault (or 'quit' to exit).\n")

            messages = [{"role": "system", "content": SYSTEM_PROMPT}]

            while True:
                try:
                    question = input("You: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nStopped.")
                    break

                if not question:
                    continue
                if question.lower() in ("quit", "exit"):
                    break

                messages.append({"role": "user", "content": question})

                try:
                    reply = call_ollama(messages, tools=ollama_tools)
                except requests.exceptions.ConnectionError:
                    print("SOC Agent: Can't reach Ollama. Is it running?\n")
                    messages.pop()
                    continue

                tool_calls = reply.get("tool_calls") or []

                if tool_calls:
                    messages.append(reply)
                    for call in tool_calls:
                        fn = call["function"]
                        name = fn["name"]
                        args = fn.get("arguments") or {}
                        if isinstance(args, str):
                            args = json.loads(args)

                        print(f"  [calling tool: {name}({args})]")
                        result = await session.call_tool(name, args)
                        result_text = extract_tool_result_text(result)

                        messages.append({
                            "role": "tool",
                            "content": result_text,
                        })

                    final = call_ollama(messages, tools=ollama_tools)
                    messages.append(final)
                    print(f"SOC Agent: {final.get('content', '').strip()}\n")
                else:
                    messages.append(reply)
                    print(f"SOC Agent: {reply.get('content', '').strip()}\n")


if __name__ == "__main__":
    asyncio.run(run_agent())
