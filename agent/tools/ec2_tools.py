"""
EC2 Tools - Get security group details
"""
import boto3
from strands import tool


@tool
def get_security_group_details(security_group_id: str) -> dict:
    """
    Retrieve details about a specific security group.

    Args:
        security_group_id: The security group ID (e.g. sg-12345abc)

    Returns:
        A dictionary with security group name, description, and rules
    """
    try:
        ec2 = boto3.client("ec2", region_name="us-east-1")

        response = ec2.describe_security_groups(
            GroupIds=[security_group_id]
        )

        groups = response.get("SecurityGroups", [])
        if not groups:
            return {"success": False, "error": f"Security group {security_group_id} not found"}

        group = groups[0]
        inbound_rules = []
        for rule in group.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                inbound_rules.append({
                    "protocol":    rule.get("IpProtocol"),
                    "from_port":   rule.get("FromPort"),
                    "to_port":     rule.get("ToPort"),
                    "cidr":        ip_range.get("CidrIp"),
                    "description": ip_range.get("Description", "No description")
                })

        return {
            "success":             True,
            "group_id":            group.get("GroupId"),
            "group_name":          group.get("GroupName"),
            "description":         group.get("Description"),
            "vpc_id":              group.get("VpcId"),
            "inbound_rules":       inbound_rules,
            "outbound_rule_count": len(group.get("IpPermissionsEgress", []))
        }
    except Exception as e:
        return {"success": False, "error": str(e)}