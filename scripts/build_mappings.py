"""One-shot generator for data/attack_mappings.csv (Phase 2 core + expansion).

Rows are defined as Python lists so csv.writer handles all quoting; regex
fields use raw strings. Re-runnable: output is deterministic.
"""
import csv

HDR = ["mapping_id", "source_format", "event_action_pattern", "ext_keys",
       "ext_value_pattern", "match_type", "is_core", "technique_id", "tactic",
       "base_confidence", "visibility_hint", "evidence_ref", "sigma_rule_id", "notes"]

R = []


def a(*x):
    R.append(list(x))


a("M001","evtx",r"^logon_failure$","","","regex",True,"T1110.001","credential-access",0.60,3,"https://attack.mitre.org/techniques/T1110/001/","","4625 failed logon; password-guessing prior")
a("M002","evtx",r"^process_created$","newprocessname",r'(?i)\\(powershell|pwsh|powershell_ise)\.exe"?$',"regex",True,"T1059.001","execution",0.70,3,"https://attack.mitre.org/techniques/T1059/001/","","PowerShell family spawn")
a("M003","evtx",r"^process_created$","newprocessname",r'(?i)\\cmd\.exe"?$',"regex",True,"T1059.003","execution",0.70,3,"https://attack.mitre.org/techniques/T1059/003/","","cmd.exe spawn")
a("M004","evtx",r"^process_created$","commandline",r"(?i)(?=.*(\.downloadstring\(|\.downloadfile\(|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|\bwget\b|\bcurl\b))(?=.*(\biex\b|invoke-expression))","regex",True,"T1059.001","execution",0.75,3,"https://attack.mitre.org/techniques/T1059/001/","","download+IEX cradle combo")
a("M005","evtx",r"^process_created$","commandline",r'(?i)\bschtasks(\.exe)?"?\s+[-/]create\b',"regex",True,"T1053.005","persistence",0.75,3,"https://attack.mitre.org/techniques/T1053/005/","92626ddd-662c-49e3-ac59-f6535f12d189","schtasks -/create on command line")
a("M006","evtx",r"^task_created$","","","exact",True,"T1053.005","persistence",0.85,4,"https://attack.mitre.org/techniques/T1053/005/","92626ddd-662c-49e3-ac59-f6535f12d189","dedicated 4698 event")
a("M007","evtx",r"^task_modified$","","","exact",True,"T1053.005","persistence",0.80,4,"https://attack.mitre.org/techniques/T1053/005/","","dedicated 4702 event")
a("M008","evtx",r"^new_service_installed$","","","exact",True,"T1543.003","persistence",0.80,4,"https://attack.mitre.org/techniques/T1543/003/","","any SCM 7045 install")
a("M009","evtx",r"^new_service_installed$","imagepath",r"(?i)(powershell|%comspec%|cmd\.exe|-enc |-encodedcommand|rundll32|mshta|\\temp\\|appdata)","regex",True,"T1543.003","persistence",0.85,4,"https://attack.mitre.org/techniques/T1543/003/","1d61f71d-59d2-479e-9562-4ff5f4ead16b","shell/script tokens in ImagePath")
a("M010","evtx",r"^user_account_created$","targetusername","","exists",True,"T1136.001","persistence",0.85,4,"https://attack.mitre.org/techniques/T1136/001/","66b6be3d-55d0-4f47-9855-d69df21740ea","4720 local account creation")
a("M011","evtx",r"^member_added_to_group$","targetusername",r"(?i).*(administrators|account.operators|backup.operators|remote.desktop.users|sudo|wheel).*","regex",True,"T1078.003","privilege-escalation",0.85,3,"https://attack.mitre.org/techniques/T1078/003/", "", "4732 local-group grant; 4728/4756 future EVENTID_MAP")
a("M012","evtx",r"^kerberos_pre_auth_failed$","","","exact",True,"T1110.003","credential-access",0.75,2,"https://attack.mitre.org/techniques/T1110/003/", "", "pre-auth failure evidence; correlation still future work")
a("M013","evtx",r"^network_share_accessed$","sharename",r"(?i)(?:^|.*[\\/])ADMIN\$$","regex",True,"T1021.002","lateral-movement",0.65,3,"https://attack.mitre.org/techniques/T1021/002/","","ADMIN$ share access")
a("M014","evtx",r"^audit_log_cleared$","","","exact",True,"T1685.005","defense-evasion",0.95,4,"https://attack.mitre.org/techniques/T1685/005/","d99b79d2-0a6f-4f46-ad8b-260b6e17f982","1102 definitive indicator (v19 id)")
a("M015","aws_cloudtrail",r"^ConsoleLogin$","error_code error_message",r"(?i)failed","regex",True,"T1110","credential-access",0.70,3,"https://attack.mitre.org/techniques/T1110/","6393e346-1977-46ef-8987-ad414a145fad","sign-in failure text; first-found key wins")
a("M016","aws_cloudtrail",r"^(StopLogging|DeleteTrail)$","event_source",r"^cloudtrail\.amazonaws\.com$","regex",True,"T1685.002","defense-evasion",0.90,4,"https://attack.mitre.org/techniques/T1685/002/","4db60cc0-36fb-42b7-9b58-a5b53019fb74","impair cloud audit logging")
a("M017","aws_cloudtrail",r"^CreateAccessKey$","request_params","userName","exists",True,"T1098.001","persistence",0.70,4,"https://attack.mitre.org/techniques/T1098/001/","0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2","key creation; self-filter not expressible")
a("M018","aws_cloudtrail",r"^(AttachUserPolicy|AttachRolePolicy)$","","","regex",True,"T1098.003","persistence",0.85,3,"https://attack.mitre.org/techniques/T1098/003/","","policy attach; priv-esc path")
a("M019","zeek",r"^SSH::Password_Guessing$","","","exact",True,"T1110.001","credential-access",0.85,3,"https://attack.mitre.org/techniques/T1110/001/","","Zeek threshold notice verbatim")
a("M020","zeek",r"^SSH::Login_By_Password_Guesser$","","","exact",True,"T1110.001","credential-access",0.90,4,"https://attack.mitre.org/techniques/T1110/001/", "", "modern Zeek login-by-guesser notice")
a("M021","evtx",r"^logon_success$","","","exact",False,"T1078","defense-evasion",0.45,3,"https://attack.mitre.org/techniques/T1078/","","baseline noise; multi-tactic technique")
a("M022","evtx",r"^logon_success$","logontype",r"^10$","regex",False,"T1021.001","lateral-movement",0.60,3,"https://attack.mitre.org/techniques/T1021/001/","","LogonType 10 RDP")
a("M023","evtx",r"^logon_success$","logontype ipaddress",r"^3$","heuristic",False,"T1021","lateral-movement",0.35,2,"https://attack.mitre.org/techniques/T1021/","","type-3 machine-account noise")
a("M024","evtx",r"^logon_failure$","substatus status",r"(?i)0xc000006[4ad]","regex",False,"T1110","credential-access",0.50,3,"https://attack.mitre.org/techniques/T1110/","","NTSTATUS bad-password codes")
a("M025","evtx",r"^explicit_credential_logon$","targetservername","","exists",False,"T1078","privilege-escalation",0.35,3,"https://attack.mitre.org/techniques/T1078/","","noisy baseline event")
a("M026","evtx",r"^explicit_credential_logon$","processname",r"(?i)\\runas\.exe$","regex",False,"T1078","privilege-escalation",0.55,3,"https://attack.mitre.org/techniques/T1078/","941e5c45-cda7-4864-8cea-bbb7458d194a","runas-driven 4648")
a("M027","evtx",r"^object_access$","objecttype",r"(?i)^file$","regex",False,"T1083","discovery",0.30,1,"https://attack.mitre.org/techniques/T1083/","","high-volume generic signal")
a("M028","evtx",r"^object_access$","objectname",r"(?i).*\\users\\.*","regex",False,"T1005","collection",0.40,1,"https://attack.mitre.org/techniques/T1005/","","user-profile document access")
a("M029","evtx",r"^special_privilege_logon$","privilegelist",r".*Se(Debug|Tcb|CreateToken|LoadDriver|TakeOwnership|EnableDelegation)Privilege.*","regex",False,"T1078","privilege-escalation",0.55,3,"https://attack.mitre.org/techniques/T1078/","","high-privilege token assignment")
a("M030","evtx",r"^process_created$","newprocessname",r'(?i)\\wmic\.exe"?$',"regex",False,"T1047","execution",0.70,3,"https://attack.mitre.org/techniques/T1047/","","WMI CLI spawn")
a("M031","evtx",r"^process_created$","commandline",r'(?i)\breg(\.exe)?"?\s+(add|import)\s+.*(\brun\b|runonce|policies\\system|winlogon|image\sfile\sexecution)',"regex",False,"T1112","defense-evasion",0.70,3,"https://attack.mitre.org/techniques/T1112/", "", "autorun-key registry write")
a("M032","evtx",r"^process_created$","commandline",r'(?i)\bnet(\.exe)?"?\s+users?\s+[^&|;]*/add\b',"regex",False,"T1136.001","persistence",0.75,3,"https://attack.mitre.org/techniques/T1136/001/", "", "net user /add")
a("M033","evtx",r"^process_created$","commandline",r'(?i)\bwevtutil(\.exe)?"?\s+cl\b',"regex",False,"T1685.005","defense-evasion",0.85,4,"https://attack.mitre.org/techniques/T1685/005/", "", "wevtutil cl log clear")
a("M034","evtx",r"^process_created$","commandline",r"(?i)(?=.*powershell).*(-version 2 )","regex",False,"T1059.001","execution",0.65,2,"https://attack.mitre.org/techniques/T1059/001/","","PSv2 downgrade attempt")
a("M035","evtx",r"^process_created$","commandline",r"(?i).*(::FromBase64String|OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA).*","regex",False,"T1059.001","execution",0.75,3,"https://attack.mitre.org/techniques/T1059/001/","","encoded FromBase64String blob")
a("M036","evtx",r"^process_created$","newprocessname",r'(?i)\\whoami\.exe"?$',"regex",False,"T1033","discovery",0.55,2,"https://attack.mitre.org/techniques/T1033/", "", "benign-noisy account discovery")
a("M037","evtx",r"^process_created$","newprocessname",r'(?i)\\systeminfo\.exe"?$',"regex",False,"T1082","discovery",0.65,2,"https://attack.mitre.org/techniques/T1082/","","system info discovery")
a("M038","evtx",r"^process_created$","newprocessname",r'(?i)\\tasklist\.exe"?$',"regex",False,"T1057","discovery",0.60,2,"https://attack.mitre.org/techniques/T1057/","","process discovery")
a("M039","evtx",r"^user_account_deleted$","targetusername","","exists",False,"T1531","impact",0.60,4,"https://attack.mitre.org/techniques/T1531/","","account deletion; rare destructive")
a("M040","evtx",r"^account_locked_out$","","","exact",False,"T1110","credential-access",0.45,1,"https://attack.mitre.org/techniques/T1110/","","lockout corroboration only")
a("M041","evtx",r"^ntlm_auth_attempt$","status",r"(?i)^0x?[89abcdef][0-9a-f]{7}$","regex",False,"T1110","credential-access",0.40,2,"https://attack.mitre.org/techniques/T1110/","","failed NTLM validation")
a("M042","evtx",r"^network_share_accessed$","sharename",r"(?i)(?:^|.*)IPC\$","regex",False,"T1021.002","lateral-movement",0.40,1,"https://attack.mitre.org/techniques/T1021/002/","","IPC$ benign-heavy")
a("M043","evtx",r"^EventID-5145$","relativetargetname",r"(?i)remcom_(stdin|stdout|stderr)","regex",False,"T1021.002","lateral-movement",0.85,1,"https://attack.mitre.org/techniques/T1021/002/","","impacket psexec RemCom pipes")
a("M044","evtx",r"^service_state_changed$","param1",r"(?i)(defender|sysmon|edr|crowdstrike|sentinel ?one|carbon ?black|cylance|mcafee|sophos|symantec|trend ?micro|bitdefender|kaspersky|eset)","regex",False,"T1685","defense-evasion",0.50,3,"https://attack.mitre.org/techniques/T1685/","","security-tool service stopped")
a("M045","evtx",r"^new_service_installed$","imagepath",r"(?i)(\\appdata\\|\\windows\\temp\\|\\users\\public\\|\\127\.0\.0\.1|\\localhost)","regex",False,"T1543.003","persistence",0.85,4,"https://attack.mitre.org/techniques/T1543/003/","26481afe-db26-4228-b264-25a29fe6efc7","suspicious install folder")
a("M046","evtx",r"^new_service_installed$","imagepath",r"(?i).*(powershell|%comspec%|cmd\.exe|-enc |-encodedcommand|rundll32|mshta).*","regex",False,"T1569.002","execution",0.70,4,"https://attack.mitre.org/techniques/T1569/002/","","service executes shell")
a("M047","evtx",r"^user_account_created$","targetusername",r".*\$$","regex",False,"T1136.001","persistence",0.85,4,"https://attack.mitre.org/techniques/T1136/001/","","hidden dollar-account creation")
a("M048","aws_cloudtrail",r"^ConsoleLogin$","error_code",r"^$","regex",False,"T1078.004","persistence",0.50,2,"https://attack.mitre.org/techniques/T1078/004/","77caf516-34e5-4df9-b4db-20744fea0a60","successful console login")
a("M049","aws_cloudtrail","","user_type",r"^Root$","regex",False,"T1078.004","defense-evasion",0.70,3,"https://attack.mitre.org/techniques/T1078/004/","","any root activity")
a("M050","aws_cloudtrail",r"^DeleteAccessKey$","request_params","userName","exists",False,"T1098.001","persistence",0.50,4,"https://attack.mitre.org/techniques/T1098/001/","","weak alone; correlate with create")
a("M051","aws_cloudtrail",r"^UpdateLoginProfile$","request_params","userName","exists",False,"T1098.001","persistence",0.55,4,"https://attack.mitre.org/techniques/T1098/001/","055fb148-60f8-462d-ad16-26926ce050f1","password reset for other principal")
a("M052","aws_cloudtrail",r"^UpdateAccountPasswordPolicy$","","","exact",False,"T1098","persistence",0.55,3,"https://attack.mitre.org/techniques/T1098/","","rare policy-weakening op")
a("M053","aws_cloudtrail",r"^(PutBucketPolicy|PutBucketAcl)$","request_params",r"[Pp]rincipal[\"']?\s*[:=]\s*(\{[^:]*:\s*(\[\s*)?)?[\"']?\*","regex",False,"T1530","collection",0.85,4,"https://attack.mitre.org/techniques/T1530/", "", "wildcard principal incl list form")
a("M054","aws_cloudtrail",r"^(PutBucketPolicy|PutBucketAcl)$","","","regex",False,"T1530","collection",0.70,4,"https://attack.mitre.org/techniques/T1530/","","bucket policy change generic")
a("M055","aws_cloudtrail",r"^AssumeRole$","request_params",r"(?i)arn:aws:iam::\d{12}:role/[^,\"'\\\s]*(admin|master|org)[^,\"'\\\s]*","heuristic",False,"T1550.001","defense-evasion",0.45,2,"https://attack.mitre.org/techniques/T1550/001/","","admin-named role assumption")
a("M056","aws_cloudtrail",r"^RunInstances$","request_params",r"(?is).*userdata.*","heuristic",False,"T1059.009","execution",0.50,3,"https://attack.mitre.org/techniques/T1059/009/","","FP-heavy; IaC embeds UserData")
a("M057","aws_cloudtrail",r"^(GetCallerIdentity|GetAccountAuthorizationDetails)$","","","heuristic",False,"T1580","discovery",0.45,4,"https://attack.mitre.org/techniques/T1580/","","burst aggregation required")
a("M058","aws_cloudtrail",r"(Describe|List)[A-Z][A-Za-z]*","event_source",r"(ec2|s3|iam|sts|lambda|rds)\.amazonaws\.com","heuristic",False,"T1580","discovery",0.35,4,"https://attack.mitre.org/techniques/T1580/","","infra read-only verb bursts")
a("M059","aws_cloudtrail",r"^CreateUser$","event_source",r"iam\.amazonaws\.com","regex",False,"T1136.003","persistence",0.90,4,"https://attack.mitre.org/techniques/T1136/003/","","IAM CreateUser")
a("M060","aws_cloudtrail",r"^DeleteUser$","event_source",r"iam\.amazonaws\.com","regex",False,"T1531","impact",0.85,4,"https://attack.mitre.org/techniques/T1531/","","IAM account removal")
a("M061","aws_cloudtrail",r"^DeleteFlowLogs$","event_source",r"ec2\.amazonaws\.com","regex",False,"T1685","defense-evasion",0.85,3,"https://attack.mitre.org/techniques/T1685/","","VPC flow-log destruction")
a("M062","zeek",r"^RST[OR]$","","","regex",False,"T1046","discovery",0.35,1,"https://attack.mitre.org/techniques/T1046/", "", "reset-heavy conn_state; action-only (parser drops proto)")
a("M063","zeek",r"^Scan::Port_Scan$","","","exact",False,"T1046","discovery",0.80,4,"https://attack.mitre.org/techniques/T1046/","","legacy scan analyzer notice")
a("M064","zeek",r"^Scan::Address_Scan$","","","exact",False,"T1046","discovery",0.80,4,"https://attack.mitre.org/techniques/T1046/","","legacy scan analyzer notice")
a("M065","zeek",r"^(S0|REJ|RSTO)$","","","heuristic",False,"T1046","discovery",0.45,2,"https://attack.mitre.org/techniques/T1046/","","rejected-conn scan proxy")
a("M066","zeek",r"^DNS TXT query$","query",r".{31,}","regex",False,"T1071.004","command-and-control",0.45,3,"https://attack.mitre.org/techniques/T1071/004/","","long TXT name; CDN FP risk")
a("M067","zeek",r"^DNS .* query$","z",r"[^0]","regex",False,"T1571","command-and-control",0.65,3,"https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_dns_susp_zbit_flag.yml","","z-bit flag mirror")
a("M068","zeek",r"^DNS .* query$","query",r"(?i)^.*(\.onion(\.[a-z]{2,7})*|\.hiddenservice\.net)$","regex",False,"T1048","exfiltration",0.70,3,"https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_dns_torproxy.yml","","tor proxy suffixes")
a("M069","zeek",r"^DNS .* query$","query",r"(?i)^.*(xmrpool|minexmr|monerohash|minergate|hashvault|supportxmr|crypto-pool)","regex",False,"T1496","impact",0.70,3,"https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_dns_mining_pools.yml","","mining pool domains")
a("M070","zeek",r"^DNS TXT query$","answers",r"(IEX|Invoke-Expression|cmd\.exe)","regex",False,"T1071.004","command-and-control",0.65,2,"https://attack.mitre.org/techniques/T1071/004/","","TXT exec strings; needs answers key")
a("M071","zeek",r"^POST \d{3}$","status_code host uri",r"^2\d\d$","heuristic",False,"T1041","exfiltration",0.45,3,"https://attack.mitre.org/techniques/T1041/","","successful outbound POST candidate")
a("M072","zeek",r"^POST \d{3}$","host uri","","heuristic",False,"T1071.001","command-and-control",0.35,2,"https://attack.mitre.org/techniques/T1071/001/","","generic POST prior")
a("M073","zeek",r"^CONNECT \d{3}$","host","","regex",False,"T1090.002","command-and-control",0.50,3,"https://attack.mitre.org/techniques/T1090/002/","","proxy tunneling")
a("M074","zeek",r"^PUT [0-9]{3}$","user_agent",r"(?i)webdav","regex",False,"T1048.003","exfiltration",0.55,2,"https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_http_webdav_put_request.yml","","webdav PUT exfil candidate")
a("M075","syslog",r"^cron(d)?(\[\d+\])?$","","","regex",False,"T1053.003","execution",0.45,2,"https://attack.mitre.org/techniques/T1053/003/","","cron scheduler evidence; benign default")
a("M076","syslog",r"^sudo(\[\d{1,6}\])?$","facility","authpriv","regex",False,"T1548.003","privilege-escalation",0.70,3,"https://attack.mitre.org/techniques/T1548/003/","","sudo invocation via authpriv")
a("M077","cef",r"^(deny|blocked|block|reset-both|reset-client|reset-server)$","product",r"(?i)(panorama|pan-os|firepower|firewall)","regex",False,"T1046","discovery",0.25,2,"https://attack.mitre.org/techniques/T1046/","","denied flow hints; corroboration only")
a("M078","cef",r"^account[\s_-]*created$","","","regex",False,"T1136","persistence",0.45,1,"https://attack.mitre.org/techniques/T1136/","","vendor act text passthrough")
a("M079","leef",r"^AuthFail$","","","exact",False,"T1110.001","credential-access",0.50,3,"https://attack.mitre.org/techniques/T1110/001/","","QRadar AuthFail")
a("M080","json",r"^logon_failure$","","","heuristic",False,"T1110.001","credential-access",0.45,2,"https://attack.mitre.org/techniques/T1110/001/","","ECS action-name prior")
a("M081","json","","riskeventtype",r"^passwordSpray$","regex",False,"T1110.003","credential-access",0.80,2,"https://attack.mitre.org/techniques/T1110/003/","","Entra IdP-detected spray")
a("M082","nginx",r"[A-Z]+ \d{3}","http_path",r"(?i).*(\.\./|/etc/passwd|/shell).*","regex",False,"T1190","initial-access",0.75,2,"https://attack.mitre.org/techniques/T1190/","","traversal/shell fetch attempt")
a("M083","nginx",r"[A-Z]+ \d{3}","http_path",r"(?i).*(/admin|/\.env|/wp-admin).*","regex",False,"T1190","initial-access",0.60,2,"https://attack.mitre.org/techniques/T1190/","","admin/env probing")

if __name__ == "__main__":
    bad = [r[0] for r in R if len(r) != 14]
    assert not bad, f"width errors: {bad}"
    with open("data/attack_mappings.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(HDR)
        w.writerows(R)
    print(f"wrote {len(R)} rows to data/attack_mappings.csv")
