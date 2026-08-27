# DataModel-EDR-Sentinelone.py  (v2 - method-based field access)
# SentinelOne events use FLAT dotted keys e.g. "src.process.parent.name"
# Panther's Path resolver uses nested traversal which fails for flat keys.
# All fields now use explicit event.get() via Python methods — same pattern as CB UDM.

def get_process_name(event):
    return event.get('src.process.name')

def get_process_path(event):
    return event.get('src.process.image.path')

def get_process_cmdline(event):
    return event.get('src.process.cmdline')

def get_process_pid(event):
    return event.get('src.process.pid')

def get_process_sha256(event):
    return event.get('src.process.image.sha256')

def get_process_md5(event):
    return event.get('src.process.image.md5')

def get_process_sha1(event):
    return event.get('src.process.image.sha1')

def get_process_integrity_level(event):
    return event.get('src.process.integrityLevel')

def get_process_start_time(event):
    return event.get('src.process.startTime')

def get_parent_process_name(event):
    return event.get('src.process.parent.name')

def get_parent_process_path(event):
    return event.get('src.process.parent.image.path')

def get_parent_process_cmdline(event):
    return event.get('src.process.parent.cmdline')

def get_parent_process_pid(event):
    return event.get('src.process.parent.pid')

def get_parent_process_sha256(event):
    return event.get('src.process.parent.image.sha256')

def get_hostname(event):
    return event.get('endpoint.name')

def get_os_platform(event):
    return event.get('endpoint.os')

def get_sensor_id(event):
    return event.get('agent.uuid')

def get_event_time(event):
    return event.get('event.time')

def get_event_type(event):
    return event.get('event.type')

def get_event_category(event):
    return event.get('event.category')

def get_device_ip(event):
    return event.get('src.endpoint.ip.address')

def get_network_dst_ip(event):
    return event.get('dst.ip.address')

def get_network_dst_port(event):
    return event.get('dst.port.number')

def get_network_src_ip(event):
    return event.get('src.ip.address')

def get_network_src_port(event):
    return event.get('src.port.number')

def get_network_direction(event):
    return event.get('event.network.direction')

def get_network_protocol(event):
    return event.get('event.network.protocolName')

def get_dns_request(event):
    return event.get('event.dns.request')

def get_file_name(event):
    return event.get('tgt.file.name')

def get_file_path(event):
    return event.get('tgt.file.path')

def get_file_sha256(event):
    return event.get('tgt.file.sha256')

def get_file_md5(event):
    return event.get('tgt.file.md5')

def get_target_process_name(event):
    return event.get('tgt.process.name')

def get_username(event):
    return event.get('src.process.user') or event.get('event.login.userName')

def get_user_is_admin(event):
    return event.get('event.login.isAdministratorEquivalent')
