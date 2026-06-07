import json
import random
import uuid
from datetime import datetime, timedelta


# ── Shared helpers ─────────────────────────────────────────────────────────

def _ts(base: datetime, offset_seconds: int = 0) -> str:
    return (base + timedelta(seconds=offset_seconds)).strftime('%Y-%m-%dT%H:%M:%S.000Z')


def _rand_ip(private=False):
    if private:
        return f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return f"{random.randint(40,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _rand_guid():
    return str(uuid.uuid4()).upper()


HOSTNAMES = ['WKSTN-BAKER', 'WKSTN-CRANE', 'SRV-FINANCE01', 'SRV-DC01', 'WKSTN-ALLEN']
USERNAMES = ['j.baker', 'a.crane', 'svc_backup', 'svc_deploy', 'm.allen', 'SYSTEM']
DOMAIN = 'CORP'


# ── CloudTrail (AWS) log generator ────────────────────────────────────────

def _cloudtrail_events(base_time: datetime, apt_id: str) -> list:
    events = []
    aws_user = f'arn:aws:iam::123456789012:user/{random.choice(["svc-deploy", "j.baker", "a.crane"])}'
    ec2_ip = _rand_ip()
    source_ip = _rand_ip()
    session_token = _rand_guid()

    sequence = [
        # Reconnaissance
        {
            'eventVersion': '1.08', 'userIdentity': {'type': 'IAMUser', 'arn': aws_user,
             'accessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'sessionToken': session_token},
            'eventTime': _ts(base_time, 0), 'eventSource': 'iam.amazonaws.com',
            'eventName': 'ListUsers', 'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0 Python/3.11.0 Linux/5.15',
            'requestParameters': {}, 'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}',
            'host': 'cloudtrail'
        },
        {
            'eventVersion': '1.08', 'userIdentity': {'type': 'IAMUser', 'arn': aws_user,
             'accessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'sessionToken': session_token},
            'eventTime': _ts(base_time, 45), 'eventSource': 'iam.amazonaws.com',
            'eventName': 'ListRoles', 'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0 Python/3.11.0 Linux/5.15',
            'requestParameters': {}, 'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}',
            'host': 'cloudtrail'
        },
        # Assume role (T1550.001)
        {
            'eventVersion': '1.08', 'userIdentity': {'type': 'IAMUser', 'arn': aws_user,
             'accessKeyId': 'AKIAIOSFODNN7EXAMPLE'},
            'eventTime': _ts(base_time, 312), 'eventSource': 'sts.amazonaws.com',
            'eventName': 'AssumeRole', 'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0 Python/3.11.0 Linux/5.15',
            'requestParameters': {'roleArn': 'arn:aws:iam::123456789012:role/AdminRole',
                                  'roleSessionName': 'recon-session'},
            'responseElements': {'credentials': {'accessKeyId': 'ASIAIOSFODNN7EXAMPLE',
                                                 'expiration': _ts(base_time, 4312)}},
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}',
            'host': 'cloudtrail'
        },
        # S3 data access (T1530)
        {
            'eventVersion': '1.08', 'userIdentity': {'type': 'AssumedRole',
             'arn': 'arn:aws:sts::123456789012:assumed-role/AdminRole/recon-session'},
            'eventTime': _ts(base_time, 890), 'eventSource': 's3.amazonaws.com',
            'eventName': 'GetObject', 'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0',
            'requestParameters': {'bucketName': 'corp-finance-reports',
                                  'key': 'Q4-2024/financial-summary.xlsx'},
            'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}',
            'host': 'cloudtrail'
        },
        # Exfil via S3 copy (T1537)
        {
            'eventVersion': '1.08', 'userIdentity': {'type': 'AssumedRole',
             'arn': 'arn:aws:sts::123456789012:assumed-role/AdminRole/recon-session'},
            'eventTime': _ts(base_time, 1240), 'eventSource': 's3.amazonaws.com',
            'eventName': 'CopyObject', 'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0',
            'requestParameters': {'bucketName': 'corp-staging-temp',
                                  'key': 'backup/fin-data.zip',
                                  'x-amz-copy-source': 'corp-finance-reports/Q4-2024/financial-summary.xlsx'},
            'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}',
            'host': 'cloudtrail'
        },
    ]
    return sequence


# ── Sysmon log generator ───────────────────────────────────────────────────

def _sysmon_events(base_time: datetime, apt_id: str) -> list:
    host = random.choice(HOSTNAMES[:3])
    user = f'{DOMAIN}\\{random.choice(USERNAMES[:3])}'
    c2_ip = _rand_ip()
    lsass_pid = random.randint(600, 800)
    malware_pid = random.randint(4000, 8000)
    ps_pid = random.randint(2000, 4000)

    events = [
        # EID 1 - Process creation: encoded PowerShell (T1059.001 + T1027)
        {
            'EventID': 1, 'EventTime': _ts(base_time, 120),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'CommandLine': 'powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0AA==',
            'ParentImage': 'C:\\Windows\\System32\\cmd.exe',
            'ParentCommandLine': 'cmd.exe /c start /b powershell',
            'ProcessId': ps_pid, 'ParentProcessId': random.randint(1000, 2000),
            'Hashes': 'SHA256=908B64B1971A979C7E3E8CE4621945CBA84854CB98D76367B791A6E22B5F6D53',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID 3 - Network connection: C2 beacon (T1071.001)
        {
            'EventID': 3, 'EventTime': _ts(base_time, 185),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'ProcessId': ps_pid,
            'DestinationIp': c2_ip, 'DestinationPort': 443,
            'SourceIp': _rand_ip(private=True), 'SourcePort': random.randint(49152, 65535),
            'Protocol': 'tcp', 'Initiated': True,
            'DestinationHostname': f'cdn-{random.randint(100,999)}.updates-service.net',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID 10 - Process access: LSASS (T1003.001)
        {
            'EventID': 10, 'EventTime': _ts(base_time, 340),
            'Computer': host, 'User': user,
            'SourceImage': 'C:\\Windows\\Temp\\svchost32.exe',
            'SourceProcessId': malware_pid,
            'TargetImage': 'C:\\Windows\\System32\\lsass.exe',
            'TargetProcessId': lsass_pid,
            'GrantedAccess': '0x1010',
            'CallTrace': 'C:\\Windows\\SYSTEM32\\ntdll.dll+9d404|C:\\Windows\\System32\\KERNELBASE.dll+70bf6',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID 13 - Registry: run key persistence (T1547.001)
        {
            'EventID': 13, 'EventTime': _ts(base_time, 410),
            'Computer': host, 'User': user,
            'EventType': 'SetValue',
            'TargetObject': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper',
            'Details': 'C:\\Windows\\Temp\\svchost32.exe -silent',
            'Image': 'C:\\Windows\\Temp\\svchost32.exe',
            'ProcessId': malware_pid,
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID 11 - File create: dropped payload (T1105)
        {
            'EventID': 11, 'EventTime': _ts(base_time, 95),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'ProcessId': ps_pid,
            'TargetFilename': 'C:\\Windows\\Temp\\svchost32.exe',
            'CreationUtcTime': _ts(base_time, 95),
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID 1 - Lateral movement via PsExec (T1021.002)
        {
            'EventID': 1, 'EventTime': _ts(base_time, 720),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\cmd.exe',
            'CommandLine': f'cmd.exe /c psexec.exe \\\\SRV-DC01 -u {DOMAIN}\\svc_backup -p [REDACTED] cmd.exe',
            'ParentImage': 'C:\\Windows\\Temp\\svchost32.exe',
            'ParentCommandLine': 'C:\\Windows\\Temp\\svchost32.exe -silent',
            'ProcessId': random.randint(5000, 9000),
            'ParentProcessId': malware_pid,
            'Hashes': 'SHA256=A7F2C1E4D63B8F1A2C9E5D4B7F8A1C2E3D4B5F6A7C8D9E0F1A2B3C4D5E6F7A8',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID 3 - Periodic C2 beacon (T1071.001) — 2nd beacon showing regularity
        {
            'EventID': 3, 'EventTime': _ts(base_time, 485),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'ProcessId': ps_pid,
            'DestinationIp': c2_ip, 'DestinationPort': 443,
            'SourceIp': _rand_ip(private=True), 'SourcePort': random.randint(49152, 65535),
            'Protocol': 'tcp', 'Initiated': True,
            'DestinationHostname': f'cdn-{random.randint(100,999)}.updates-service.net',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
    ]
    return events


# ── Windows Event Log generator ───────────────────────────────────────────

def _winevent_events(base_time: datetime, apt_id: str) -> list:
    host = random.choice(HOSTNAMES[:3])
    user = f'{DOMAIN}\\{random.choice(USERNAMES[:3])}'
    dc = 'SRV-DC01'
    src_ip = _rand_ip(private=True)

    events = [
        # EID 4624 - Successful logon
        {
            'EventID': 4624, 'EventTime': _ts(base_time, 60),
            'Computer': host, 'Channel': 'Security',
            'SubjectUserName': 'SYSTEM', 'SubjectDomainName': DOMAIN,
            'TargetUserName': USERNAMES[2], 'TargetDomainName': DOMAIN,
            'LogonType': 3, 'IpAddress': src_ip,
            'LogonProcessName': 'NtLmSsp', 'AuthenticationPackageName': 'NTLM',
            'WorkstationName': HOSTNAMES[0],
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID 4625 - Failed logon (credential spray)
        {
            'EventID': 4625, 'EventTime': _ts(base_time, 30),
            'Computer': dc, 'Channel': 'Security',
            'TargetUserName': 'administrator', 'TargetDomainName': DOMAIN,
            'LogonType': 3, 'IpAddress': src_ip,
            'FailureReason': 'Unknown user name or bad password',
            'SubStatus': '0xC000006A',
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': dc
        },
        # EID 4776 - NTLM auth attempt
        {
            'EventID': 4776, 'EventTime': _ts(base_time, 55),
            'Computer': dc, 'Channel': 'Security',
            'TargetUserName': USERNAMES[2], 'Workstation': HOSTNAMES[0],
            'ErrorCode': '0x0',
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': dc
        },
        # EID 4648 - Logon with explicit credentials (pass-the-hash indicator)
        {
            'EventID': 4648, 'EventTime': _ts(base_time, 715),
            'Computer': host, 'Channel': 'Security',
            'SubjectUserName': USERNAMES[0], 'SubjectDomainName': DOMAIN,
            'AccountName': USERNAMES[2], 'AccountDomain': DOMAIN,
            'TargetServerName': 'SRV-DC01',
            'ProcessName': 'C:\\Windows\\Temp\\svchost32.exe',
            'IpAddress': src_ip,
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID 4698 - Scheduled task created (T1053.005)
        {
            'EventID': 4698, 'EventTime': _ts(base_time, 820),
            'Computer': host, 'Channel': 'Security',
            'SubjectUserName': USERNAMES[2], 'SubjectDomainName': DOMAIN,
            'TaskName': '\\Microsoft\\Windows\\WindowsUpdate\\UpdateHelper',
            'TaskContent': '<Task><Actions><Exec><Command>C:\\Windows\\Temp\\svchost32.exe</Command></Exec></Actions></Task>',
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID 4103 - PowerShell module logging
        {
            'EventID': 4103, 'EventTime': _ts(base_time, 125),
            'Computer': host, 'Channel': 'Microsoft-Windows-PowerShell/Operational',
            'ContextInfo': f'Runspace ID={_rand_guid()}',
            'Payload': 'CommandInvocation(Invoke-Expression): "Invoke-Expression"\nParameterBinding(Invoke-Expression): name="Command"; value="[System.Reflection.Assembly]::LoadWithPartialName(\'Microsoft.CSharp\')"',
            'UserName': user,
            'sourcetype': 'WinEventLog:Microsoft-Windows-PowerShell/Operational',
            'index': f'ghosttrace_{apt_id}', 'host': host
        },
    ]
    return events


# ── Azure AD log generator ────────────────────────────────────────────────

def _azure_aad_events(base_time: datetime, apt_id: str) -> list:
    src_ip = _rand_ip()
    user_upn = 'j.baker@corp.onmicrosoft.com'
    admin_upn = 'admin@corp.onmicrosoft.com'

    events = [
        # MFA fatigue - repeated MFA push
        {
            'time': _ts(base_time, 0), 'category': 'SignInLogs',
            'operationName': 'Sign-in activity',
            'properties': {
                'userPrincipalName': admin_upn, 'appDisplayName': 'Azure Portal',
                'ipAddress': src_ip, 'clientAppUsed': 'Browser',
                'status': {'errorCode': 500121, 'failureReason': 'Authentication failed during strong authentication request.'},
                'authenticationDetails': [{'authenticationMethod': 'Phone app notification', 'succeeded': False}],
                'location': {'city': 'Unknown', 'countryOrRegion': 'RO'},
                'conditionalAccessStatus': 'notApplied'
            },
            'sourcetype': 'azure:aad:signin', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
        },
        # Successful sign-in after MFA fatigue
        {
            'time': _ts(base_time, 1820), 'category': 'SignInLogs',
            'operationName': 'Sign-in activity',
            'properties': {
                'userPrincipalName': admin_upn, 'appDisplayName': 'Azure Portal',
                'ipAddress': src_ip, 'clientAppUsed': 'Browser',
                'status': {'errorCode': 0, 'failureReason': None},
                'authenticationDetails': [{'authenticationMethod': 'Phone app notification', 'succeeded': True}],
                'location': {'city': 'Unknown', 'countryOrRegion': 'RO'},
                'conditionalAccessStatus': 'success'
            },
            'sourcetype': 'azure:aad:signin', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
        },
        # Conditional access policy modified (T1556.006)
        {
            'time': _ts(base_time, 2100), 'category': 'AuditLogs',
            'operationName': 'Update conditional access policy',
            'properties': {
                'initiatedBy': {'user': {'userPrincipalName': admin_upn, 'ipAddress': src_ip}},
                'targetResources': [{'displayName': 'Require MFA for All Users',
                                     'modifiedProperties': [
                                         {'displayName': 'State', 'oldValue': '"enabled"', 'newValue': '"disabled"'}
                                     ]}],
                'result': 'success'
            },
            'sourcetype': 'azure:aad:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
        },
        # New user added to Global Admin (T1098)
        {
            'time': _ts(base_time, 2450), 'category': 'AuditLogs',
            'operationName': 'Add member to role',
            'properties': {
                'initiatedBy': {'user': {'userPrincipalName': admin_upn, 'ipAddress': src_ip}},
                'targetResources': [
                    {'displayName': 'svc-monitoring@corp.onmicrosoft.com', 'type': 'User'},
                    {'displayName': 'Global Administrator', 'type': 'Role'}
                ],
                'result': 'success'
            },
            'sourcetype': 'azure:aad:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
        },
    ]
    return events


# ── GCP Audit log generator ───────────────────────────────────────────────

def _gcp_audit_events(base_time: datetime, apt_id: str) -> list:
    src_ip = _rand_ip()
    svc_account = 'svc-deploy@corp-project.iam.gserviceaccount.com'

    events = [
        # IAM policy modified (T1098)
        {
            'insertId': _rand_guid(), 'timestamp': _ts(base_time, 0),
            'logName': 'projects/corp-project/logs/cloudaudit.googleapis.com%2Factivity',
            'protoPayload': {
                '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'methodName': 'SetIamPolicy',
                'serviceName': 'iam.googleapis.com',
                'authenticationInfo': {'principalEmail': svc_account},
                'requestMetadata': {'callerIp': src_ip, 'callerSuppliedUserAgent': 'google-cloud-sdk'},
                'request': {'policy': {'bindings': [{'role': 'roles/owner',
                    'members': ['serviceAccount:exfil-svc@attacker-project.iam.gserviceaccount.com']}]}},
                'resourceName': 'projects/corp-project'
            },
            'sourcetype': 'gcp:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'gcp'
        },
        # New service account key created (T1098.001)
        {
            'insertId': _rand_guid(), 'timestamp': _ts(base_time, 180),
            'logName': 'projects/corp-project/logs/cloudaudit.googleapis.com%2Factivity',
            'protoPayload': {
                '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'methodName': 'google.iam.admin.v1.CreateServiceAccountKey',
                'serviceName': 'iam.googleapis.com',
                'authenticationInfo': {'principalEmail': svc_account},
                'requestMetadata': {'callerIp': src_ip},
                'resourceName': f'projects/corp-project/serviceAccounts/{svc_account}'
            },
            'sourcetype': 'gcp:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'gcp'
        },
        # GCS data access (T1530)
        {
            'insertId': _rand_guid(), 'timestamp': _ts(base_time, 520),
            'logName': 'projects/corp-project/logs/cloudaudit.googleapis.com%2Fdata_access',
            'protoPayload': {
                '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'methodName': 'storage.objects.get',
                'serviceName': 'storage.googleapis.com',
                'authenticationInfo': {'principalEmail': svc_account},
                'requestMetadata': {'callerIp': src_ip},
                'resourceName': 'projects/_/buckets/corp-sensitive-data/objects/employee-records.csv'
            },
            'sourcetype': 'gcp:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'gcp'
        },
    ]
    return events


# ── Benign noise ──────────────────────────────────────────────────────────

def _benign_events(base_time: datetime, apt_id: str, count: int = 15) -> list:
    events = []
    benign_processes = [
        ('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'chrome.exe --type=renderer'),
        ('C:\\Windows\\System32\\svchost.exe', 'svchost.exe -k netsvcs -p'),
        ('C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', 'OUTLOOK.EXE'),
        ('C:\\Windows\\System32\\taskhostw.exe', 'taskhostw.exe'),
        ('C:\\Windows\\explorer.exe', 'C:\\Windows\\explorer.exe'),
    ]
    for i in range(count):
        proc = random.choice(benign_processes)
        host = random.choice(HOSTNAMES)
        user = f'{DOMAIN}\\{random.choice(USERNAMES)}'
        offset = random.randint(0, 1500)
        events.append({
            'EventID': 1, 'EventTime': _ts(base_time, offset),
            'Computer': host, 'User': user,
            'Image': proc[0], 'CommandLine': proc[1],
            'ParentImage': 'C:\\Windows\\explorer.exe',
            'ProcessId': random.randint(1000, 9999),
            'ParentProcessId': random.randint(100, 999),
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        })
    return events


# ── Main dispatcher ───────────────────────────────────────────────────────

def generate_logs(apt_id: str) -> list:
    base_time = datetime.utcnow() - timedelta(hours=random.randint(2, 12))
    all_logs = []

    if apt_id == 'apt29':
        all_logs += _cloudtrail_events(base_time, apt_id)
        all_logs += _sysmon_events(base_time, apt_id)
        all_logs += _winevent_events(base_time, apt_id)

    elif apt_id == 'apt28':
        all_logs += _sysmon_events(base_time, apt_id)
        all_logs += _winevent_events(base_time, apt_id)

    elif apt_id == 'lazarus':
        all_logs += _cloudtrail_events(base_time, apt_id)
        all_logs += _sysmon_events(base_time, apt_id)
        all_logs += _winevent_events(base_time, apt_id)

    elif apt_id == 'apt41':
        all_logs += _gcp_audit_events(base_time, apt_id)
        all_logs += _sysmon_events(base_time, apt_id)
        all_logs += _winevent_events(base_time, apt_id)

    elif apt_id == 'unc3944':
        all_logs += _azure_aad_events(base_time, apt_id)
        all_logs += _sysmon_events(base_time, apt_id)
        all_logs += _winevent_events(base_time, apt_id)

    # Add benign noise
    all_logs += _benign_events(base_time, apt_id)

    # Sort by timestamp
    all_logs.sort(key=lambda x: x.get('EventTime') or x.get('eventTime') or x.get('time') or x.get('timestamp', ''))

    return all_logs


def generate_index_file(apt_id: str) -> str:
    logs = generate_logs(apt_id)
    lines = [json.dumps(log) for log in logs]
    return '\n'.join(lines)
