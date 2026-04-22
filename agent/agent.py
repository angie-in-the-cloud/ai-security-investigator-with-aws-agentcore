"""
CloudTrail Security Event Investigator Agent
"""
from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel

app = BedrockAgentCoreApp()


def get_agent():
    """
    Initialize the agent with lazy loading.
    We do this inside a function rather than at the top of the file
    to avoid slow startup times when the agent first wakes up.
    """
    from tools import (
        get_cloudtrail_events,
        get_security_group_details,
        send_investigation_email,
        create_security_finding
    )

    model = BedrockModel(
        model_id="us.anthropic.claude-sonnet-4-6"
    )

    return Agent(
        model=model,
        tools=[
            get_cloudtrail_events,
            get_security_group_details,
            send_investigation_email,
            create_security_finding
        ],
        system_prompt="""
        You are a cloud security investigator agent. Your job is to analyze
        AWS security events, understand what happened, and communicate it
        clearly to non-technical stakeholders.

        When you receive a security event:

        1. Use get_cloudtrail_events to look up what else the same user
           did in the 60 minutes before and after this event.

        2. If the event involves a security group change, use
           get_security_group_details to get more context about the
           affected firewall rule.

        3. Assess the severity:
           - CRITICAL: Changes that expose sensitive ports (22, 3389, 3306,
             5432) to the entire internet (0.0.0.0/0)
           - HIGH: Changes that expose any port to the entire internet
           - MEDIUM: Changes that open access to a broad but not universal
             IP range
           - LOW: Changes to egress rules or non-sensitive configurations
           - INFORMATIONAL: Rule removals that improve security posture

        4. Use send_investigation_email to send a clear, plain-English
           email explaining: what changed, who made the change, when,
           what the risk is, and what action to take.

        5. Use create_security_finding to log an official record in
           Security Hub.

        Be concise, clear, and avoid unnecessary jargon.
        """
    )


@app.entrypoint
def handler(payload, context):
    """Handle incoming security events from Lambda"""
    agent = get_agent()

    event_name    = payload.get("event_name", "UnknownEvent")
    event_time    = payload.get("event_time", "")
    user_identity = payload.get("user_identity", {})
    source_ip     = payload.get("source_ip", "unknown")
    resources     = payload.get("resources", [])
    raw_event     = payload.get("raw_event", {})

    username = (
        user_identity.get("userName")
        or user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
        or user_identity.get("arn", "unknown")
    )

    prompt = f"""
    A security event has occurred in this AWS account. Please investigate
    and report on it.

    Event Name: {event_name}
    Time: {event_time}
    Performed By: {username}
    Source IP Address: {source_ip}
    Affected Resources: {resources}

    Raw Event Details:
    {raw_event}

    Please investigate this event, check for related activity in the
    past hour from this user, assess the risk, send an email summary,
    and create a Security Hub finding.
    """

    result = agent(prompt)
    return {"status": "completed", "result": str(result)}


if __name__ == "__main__":
    app.run()