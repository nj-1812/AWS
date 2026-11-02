"""AgentCore Runtime entrypoint. Deployed as a code asset by the CDK stack.

Invoke payload: {"template": "<IaC text>", "deep": false}
"""

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from archguard.agents.review import review_template

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload: dict) -> dict:
    template = payload.get("template", "")
    if not template.strip():
        return {"error": "payload.template is required"}
    return review_template(template, deep=bool(payload.get("deep", False)))


if __name__ == "__main__":
    app.run()
