##lastest agent version update with tools

import os
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient

# 1. SETUP
myEndpoint = ""
myAgentName = ""

print(f"Connecting to Agent: '{myAgentName}'...")
project_client = AIProjectClient(
    endpoint=myEndpoint,
    credential=DefaultAzureCredential(),
)

# 2. DEFINE TOOLS (Crucial Step)
# ACTION REQUIRED: You must replace the string below with your ACTUAL Full Resource ID.
tool1 = {
    "type": "",
    "server_label": "",
    "server_url": "",
    "require_approval": "",
    "project_connection_id": ""
}

tool2 = {
    "type": "",
    "server_label": "",
    "server_url": "",
    "require_approval": "",
    "project_connection_id": ""
}

# 3. DEFINE AGENT (With Instructions)
agent_definition = {
    "kind": "",
    "model": "",
    "instructions": """
You are a Cyber Security Analyst.
IMPORTANT: You have full permission to execute all attached tools immediately.
Do not ask for confirmation. Run tools automatically.
""",
    # FIX: Passing list of tools with CORRECT IDs
    "tools": [tool1, tool2]
}

# 4. EXECUTE (Create Version)
print("Creating new agent version...")

try:
    # create_version applies the definition to the new snapshot
    agent = project_client.agents.create_version(
        agent_name=myAgentName,
        definition=agent_definition
    )

    print(f"SUCCESS: Agent '{agent.name}' updated!")
    print(f"New Version ID: {agent.version}")
    print("----------------------------------------------------------------")
    print(f"CRITICAL STEP: Go to your Logic App and change 'version': to '{agent.version}'")
    print("----------------------------------------------------------------")

except Exception as e:
    print(f"Operation failed: {e}")