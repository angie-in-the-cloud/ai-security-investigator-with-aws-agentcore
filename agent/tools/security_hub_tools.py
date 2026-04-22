"""
Security Hub Tools - Create official security findings
"""
import boto3
from strands import tool
from datetime import datetime, timezone


@tool
def create_security_finding(
    title: str,
    description: str,
    severity: str,
    event_name: str,
    username: str,
    resource_id: str = "aws:cloudtrail:event"
) -> dict:
    """
    Create an official security finding in AWS Security Hub.

    Args:
        title: Short descriptive title for the finding
        description: Full description of what happened and the risk
        severity: CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL
        event_name: The CloudTrail event name
        username: The user who performed the action
        resource_id: The affected AWS resource identifier

    Returns:
        Dictionary with success status and finding ID
    """
    try:
        sts        = boto3.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        region     = "us-east-1"
        now        = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        finding_id = f"cloudtrail-investigator-{event_name}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        severity_map = {
            "CRITICAL":      {"Label": "CRITICAL",      "Normalized": 90},
            "HIGH":          {"Label": "HIGH",          "Normalized": 70},
            "MEDIUM":        {"Label": "MEDIUM",        "Normalized": 40},
            "LOW":           {"Label": "LOW",           "Normalized": 20},
            "INFORMATIONAL": {"Label": "INFORMATIONAL", "Normalized": 0}
        }

        finding = {
            "SchemaVersion": "2018-10-08",
            "Id":            finding_id,
            "ProductArn":    f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
            "GeneratorId":   "cloudtrail-investigator-agent",
            "AwsAccountId":  account_id,
            "Types":         ["TTPs/Initial Access/Unusual Activity Detected"],
            "CreatedAt":     now,
            "UpdatedAt":     now,
            "Severity":      severity_map.get(severity.upper(), severity_map["MEDIUM"]),
            "Title":         title,
            "Description":   description,
            "Remediation": {
                "Recommendation": {
                    "Text": "Review the CloudTrail event and take corrective action if needed.",
                    "Url":  f"https://console.aws.amazon.com/cloudtrail/home?region={region}#/events"
                }
            },
            "Resources": [{
                "Type":   "Other",
                "Id":     resource_id,
                "Region": region
            }],
            "Compliance":    {"Status": "FAILED"},
            "WorkflowState": "NEW",
            "RecordState":   "ACTIVE",
            "Note": {
                "Text":      f"Investigated by CloudTrail Investigator Agent | User: {username} | Event: {event_name} | NIST 800-53: SI-4 | SOC 2: CC7.2",
                "UpdatedBy": "cloudtrail-investigator-agent",
                "UpdatedAt": now
            }
        }

        securityhub = boto3.client("securityhub", region_name=region)
        response    = securityhub.batch_import_findings(Findings=[finding])

        return {
            "success":      True,
            "finding_id":   finding_id,
            "failed_count": response.get("FailedCount", 0)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}