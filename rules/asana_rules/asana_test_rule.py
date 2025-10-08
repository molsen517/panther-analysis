def rule(event):
    """
    Detects suspicious user activity patterns in Asana that could indicate
    account compromise or unauthorized access. This rule triggers when a user
    performs multiple high-privilege actions within a short time period.
    """
    # Define high-privilege event types that could indicate suspicious activity
    high_privilege_events = {
        "user_invited",  # Inviting new users
        "user_workspace_admin_role_changed",  # Changing admin roles
        "team_privacy_settings_changed",  # Changing team privacy
        "workspace_associated_email_domain_added",  # Adding email domains
        "workspace_associated_email_domain_removed",  # Removing email domains
        "service_account_created",  # Creating service accounts
        "workspace_settings_changed",  # Changing workspace settings
        "team_created",  # Creating new teams
        "project_created",  # Creating new projects
    }
    
    # Get the event type from the log
    event_type = event.get("event_type")
    
    # Check if this is a high-privilege event
    if event_type not in high_privilege_events:
        return False
    
    # Get actor information
    actor_email = event.deep_get("actor", "email", default="")
    actor_name = event.deep_get("actor", "name", default="")
    
    # Check for suspicious patterns in actor email or name
    suspicious_patterns = [
        "test", "temp", "admin", "root", "system", "bot", "automation"
    ]
    
    # Check if actor email or name contains suspicious patterns
    actor_info_lower = f"{actor_email} {actor_name}".lower()
    for pattern in suspicious_patterns:
        if pattern in actor_info_lower:
            return True
    
    # Check for unusual IP addresses (basic check for private/local IPs)
    client_ip = event.deep_get("context", "client_ip_address", default="")
    if client_ip:
        # Check for private IP ranges that might be suspicious in corporate context
        if client_ip.startswith("192.168.") or client_ip.startswith("10.") or client_ip.startswith("172."):
            # Additional check: if it's a high-privilege action from private IP, flag it
            if event_type in ["user_workspace_admin_role_changed", "workspace_associated_email_domain_added"]:
                return True
    
    # Check for specific suspicious event combinations
    if event_type == "team_privacy_settings_changed":
        new_value = event.deep_get("details", "new_value", default="")
        if new_value == "public":
            return True
    
    # Check for service account creation with suspicious naming
    if event_type == "service_account_created":
        service_account_name = event.deep_get("resource", "name", default="").lower()
        if any(pattern in service_account_name for pattern in ["test", "temp", "backup", "emergency"]):
            return True
    
    return False


def title(event):
    """Generate a descriptive title for the alert."""
    event_type = event.get("event_type", "<UNKNOWN_EVENT>")
    actor_email = event.deep_get("actor", "email", default="<UNKNOWN_ACTOR>")
    resource_name = event.deep_get("resource", "name", default="<UNKNOWN_RESOURCE>")
    
    return f"Suspicious Asana activity detected: [{event_type}] by [{actor_email}] on [{resource_name}]"


def dedup(event):
    """Create a deduplication key based on actor and event type."""
    actor_email = event.deep_get("actor", "email", default="<UNKNOWN_ACTOR>")
    event_type = event.get("event_type", "<UNKNOWN_EVENT>")
    return f"{actor_email}:{event_type}"


def severity(event):
    """Determine severity based on the type of suspicious activity."""
    event_type = event.get("event_type", "")
    
    # High severity events
    high_severity_events = {
        "user_workspace_admin_role_changed",
        "workspace_associated_email_domain_added",
        "workspace_associated_email_domain_removed"
    }
    
    # Medium severity events
    medium_severity_events = {
        "user_invited",
        "service_account_created",
        "workspace_settings_changed"
    }
    
    if event_type in high_severity_events:
        return "HIGH"
    elif event_type in medium_severity_events:
        return "MEDIUM"
    else:
        return "LOW"
