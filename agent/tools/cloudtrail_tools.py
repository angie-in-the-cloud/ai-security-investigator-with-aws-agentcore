"""
CloudTrail Tools - Query related security events
"""
import boto3
from strands import tool
from datetime import datetime, timedelta, timezone


@tool
def get_cloudtrail_events(username: str, minutes_back: int = 60) -> dict:
    """
    Look up recent CloudTrail events for a specific user.

    Args:
        username: The IAM username or ARN to look up
        minutes_back: How many minutes of history to retrieve (default 60)

    Returns:
        A dictionary containing recent events for that user
    """
    try:
        cloudtrail = boto3.client("cloudtrail", region_name="us-east-1")

        end_time   = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=minutes_back)

        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    "AttributeKey": "Username",
                    "AttributeValue": username
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=20
        )

        events = []
        for event in response.get("Events", []):
            events.append({
                "event_name":   event.get("EventName"),
                "event_time":   event.get("EventTime").isoformat() if event.get("EventTime") else None,
                "event_source": event.get("EventSource"),
                "resources":    [r.get("ResourceName") for r in event.get("Resources", [])]
            })

        return {
            "success":     True,
            "username":    username,
            "event_count": len(events),
            "time_window": f"Last {minutes_back} minutes",
            "events":      events
        }
    except Exception as e:
        return {"success": False, "error": str(e)}