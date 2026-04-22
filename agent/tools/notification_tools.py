"""
Notification Tools - Send investigation emails via SES
"""
import boto3
import json
from strands import tool
from datetime import datetime


def get_notification_config():
    """Retrieve email configuration from Secrets Manager"""
    client = boto3.client("secretsmanager", region_name="us-east-1")
    response = client.get_secret_value(
        SecretId="cloudtrail-investigator/notifications"
    )
    return json.loads(response["SecretString"])


SEVERITY_COLORS = {
    "CRITICAL":      "#e53e3e",
    "HIGH":          "#dd6b20",
    "MEDIUM":        "#d69e2e",
    "LOW":           "#3182ce",
    "INFORMATIONAL": "#38a169"
}


@tool
def send_investigation_email(
    subject: str,
    what_happened: str,
    who_did_it: str,
    when_it_happened: str,
    risk_assessment: str,
    recommended_action: str,
    severity: str
) -> dict:
    """
    Send a plain-English security investigation summary email.

    Args:
        subject: Email subject line
        what_happened: Clear description of the event in plain English
        who_did_it: Who performed the action (username, IP address)
        when_it_happened: Timestamp of the event
        risk_assessment: What the risk is and why it matters
        recommended_action: What the recipient should do
        severity: CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL

    Returns:
        Dictionary with success status and email message ID
    """
    try:
        config = get_notification_config()
        ses    = boto3.client("ses", region_name="us-east-1")

        color = SEVERITY_COLORS.get(severity.upper(), "#718096")

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 640px;
                     margin: 0 auto; color: #2d3748;">
          <div style="background: {color}; padding: 24px; border-radius: 8px 8px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 22px;">Security Event Detected</h1>
            <span style="background: rgba(255,255,255,0.25); color: white;
                         padding: 4px 12px; border-radius: 20px;
                         font-size: 14px; font-weight: bold;">
              {severity.upper()}
            </span>
          </div>
          <div style="background: #f7fafc; padding: 24px;">
            <div style="background: white; border-radius: 8px; padding: 20px;
                        margin-bottom: 16px; border-left: 4px solid {color};">
              <h2 style="margin: 0 0 12px 0; font-size: 16px;">What Happened</h2>
              <p style="margin: 0; line-height: 1.6;">{what_happened}</p>
            </div>
            <div style="background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px;">
              <table style="width: 100%; border-collapse: collapse;">
                <tr>
                  <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;
                             font-weight: bold; width: 140px; color: #718096; font-size: 13px;">
                    PERFORMED BY
                  </td>
                  <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;">{who_did_it}</td>
                </tr>
                <tr>
                  <td style="padding: 8px 0; font-weight: bold; color: #718096; font-size: 13px;">
                    TIME
                  </td>
                  <td style="padding: 8px 0;">{when_it_happened}</td>
                </tr>
              </table>
            </div>
            <div style="background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px;">
              <h2 style="margin: 0 0 12px 0; font-size: 16px;">Risk Assessment</h2>
              <p style="margin: 0; line-height: 1.6;">{risk_assessment}</p>
            </div>
            <div style="background: #f0fff4; border-radius: 8px; padding: 20px;">
              <h2 style="margin: 0 0 12px 0; font-size: 16px;">Recommended Action</h2>
              <p style="margin: 0; line-height: 1.6;">{recommended_action}</p>
            </div>
          </div>
          <div style="padding: 16px 24px; background: #edf2f7; font-size: 12px; color: #718096;">
            This alert was generated automatically by the CloudTrail Security Event Investigator Agent.
          </div>
        </body>
        </html>
        """

        response = ses.send_email(
            Source=config["sender_email"],
            Destination={"ToAddresses": [config["recipient_email"]]},
            Message={
                "Subject": {"Data": f"[{severity.upper()}] {subject}"},
                "Body": {
                    "Html": {"Data": html},
                    "Text": {"Data": (
                        f"Security Event: {subject}\n\n"
                        f"What Happened: {what_happened}\n"
                        f"Performed By: {who_did_it}\n"
                        f"Time: {when_it_happened}\n"
                        f"Risk: {risk_assessment}\n"
                        f"Action: {recommended_action}"
                    )}
                }
            }
        )

        return {"success": True, "message_id": response["MessageId"]}
    except Exception as e:
        return {"success": False, "error": str(e)}