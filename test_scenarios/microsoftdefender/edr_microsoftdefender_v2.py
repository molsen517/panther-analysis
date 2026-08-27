# DataModel-EDR-MicrosoftDefender.py  (v2 - method-based field access)
# Defender AdvancedHunting events arrive in Azure Monitor format:
#   { "time": "...", "tenantId": "...", "category": "...", "properties": { ... } }
# Panther may not flatten properties{} before detection/DataModel runtime.
# All fields now use Python methods accessing event.get('properties', {}).get(field)

def _props(event):
    """Helper — returns the properties dict, handles both flat and nested."""
    props = event.get('properties')
    if isinstance(props, dict):
        return props
    # If Panther flattened properties, fields are at top level
    return event

def get_process_name(event):
    return _props(event).get('FileName')

def get_process_path(event):
    folder = _props(event).get('FolderPath') or ''
    fname  = _props(event).get('FileName') or ''
    if folder and fname:
        return folder.rstrip('\\') + '\\' + fname
    return folder or fname or None

def get_process_cmdline(event):
    return _props(event).get('ProcessCommandLine')

def get_process_pid(event):
    return _props(event).get('ProcessId')

def get_process_sha256(event):
    return _props(event).get('SHA256')

def get_process_md5(event):
    return _props(event).get('MD5')

def get_process_sha1(event):
    return _props(event).get('SHA1')

def get_process_integrity_level(event):
    return _props(event).get('ProcessIntegrityLevel')

def get_process_start_time(event):
    return _props(event).get('ProcessCreationTime')

def get_parent_process_name(event):
    return _props(event).get('InitiatingProcessFileName')

def get_parent_process_path(event):
    folder = _props(event).get('InitiatingProcessFolderPath') or ''
    fname  = _props(event).get('InitiatingProcessFileName') or ''
    if folder and fname:
        return folder.rstrip('\\') + '\\' + fname
    return folder or fname or None

def get_parent_process_cmdline(event):
    return _props(event).get('InitiatingProcessCommandLine')

def get_parent_process_pid(event):
    return _props(event).get('InitiatingProcessId')

def get_parent_process_sha256(event):
    return _props(event).get('InitiatingProcessSHA256')

def get_username(event):
    return _props(event).get('AccountName')

def get_hostname(event):
    return _props(event).get('DeviceName')

def get_os_platform(event):
    return _props(event).get('OSPlatform')

def get_sensor_id(event):
    return _props(event).get('DeviceId')

def get_event_time(event):
    return _props(event).get('Timestamp') or event.get('time')

def get_event_type(event):
    return _props(event).get('ActionType')

def get_event_category(event):
    at = (_props(event).get('ActionType') or '').lower()
    if 'process' in at:
        return 'PROCESS'
    if any(x in at for x in ('network', 'connection', 'dns')):
        return 'NETWORK'
    if 'file' in at:
        return 'FILE'
    if any(x in at for x in ('logon', 'login', 'auth')):
        return 'AUTH'
    if 'registry' in at:
        return 'REGISTRY'
    return None

def get_device_ip(event):
    return _props(event).get('PublicIP')

def get_network_dst_ip(event):
    return _props(event).get('RemoteIP')

def get_network_dst_port(event):
    return _props(event).get('RemotePort')

def get_network_src_ip(event):
    return _props(event).get('LocalIP')

def get_network_src_port(event):
    return _props(event).get('LocalPort')

def get_network_direction(event):
    at = (_props(event).get('ActionType') or '')
    if 'Inbound' in at:
        return 'inbound'
    if 'Connection' in at:
        return 'outbound'
    return None

def get_network_protocol(event):
    return _props(event).get('Protocol')

def get_dns_request(event):
    return _props(event).get('RemoteUrl')

def get_file_name(event):
    return _props(event).get('FileName')

def get_file_path(event):
    folder = _props(event).get('FolderPath') or ''
    fname  = _props(event).get('FileName') or ''
    if folder and fname:
        return folder.rstrip('\\') + '\\' + fname
    return folder or fname or None

def get_file_sha256(event):
    return _props(event).get('SHA256')

def get_file_md5(event):
    return _props(event).get('MD5')

def get_user_is_admin(event):
    return _props(event).get('ProcessTokenElevation') == 'TokenElevationTypeFull'

def get_user_sid(event):
    return _props(event).get('AccountSid')
