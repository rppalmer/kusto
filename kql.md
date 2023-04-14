## Identity 

Custom table join using Sentinel Watchlist
```
let CustomUserTable = IdentityInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated,*) by AccountName
| where AccountName in~ ((_GetWatchlist('CustomUserTable') | project AccountName));
let DeviceInfoTable = DeviceInfo
| where TimeGenerated > ago(30d)
| extend AccountName = tostring(parse_json(LoggedOnUsers[0].UserName))
| where AccountName != ""
| summarize arg_max(TimeGenerated,*) by DeviceName
| project TimeGenerated,DeviceName,JoinType,AccountName,DeviceId
| join (CustomUserTable) on AccountName;
DeviceInfoTable
| where TimeGenerated > ago($Days`d)
| project TimeGenerated,AccountName,AccountUPN,DeviceName,Department,Manager,Phone,IsAccountEnabled
| order by TimeGenerated desc
```

Count of failed attempts by day/account
```
SecurityEvent
| where EventID == 4625 and AccountType =~ "User"
| where IpAddress !in ("127.0.0.1", "::1")
| where Account contains "root"
| summarize count() by datetime_part('day',TimeGenerated),Account
```

Advanced sign in details 
```
SigninLogs 
| mv-expand parse_json("DeviceDetail")
| extend OS = DeviceDetail["operatingSystem"]
| extend authenticationMethod_ = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod) 
| extend authenticationSuccess_ = tostring(parse_json(AuthenticationDetails)[0].succeeded)
| extend city = tostring(parse_json(LocationDetails).city)
| extend state = tostring(parse_json(LocationDetails).state)
| extend trustedNamesLocation = tostring(parse_json(NetworkLocationDetails)[0].networkNames)
| extend country = tostring(parse_json(NetworkLocationDetails)[1].networkNames)
| project TimeGenerated,AlternateSignInName,Identity,AppDisplayName,OS,authenticationSuccess_,authenticationMethod_,city,state,country,trustedNamesLocation,IPAddress,OperationName,ResultDescription,Level,Location
```

Query password change events
```
AuditLogs
| extend InitiatedByDetails = todynamic(InitiatedBy)
| extend User = InitiatedByDetails.user.userPrincipalName
| where OperationName contains "password" and OperationName contains "change"
| where User contains "fivins"
```

Custom Dynamic List and search sign-in logs
```
let apps = dynamic(["App A", "App B"]);
SigninLogs
| where AppDisplayName in~ (apps)
| summarize arg_max(TimeGenerated,*) by AppDisplayName
```

Get Device Compliance managed info 
```
SigninLogs
| extend DD = todynamic(DeviceDetail)
| extend Compliant = DD.isCompliant
| extend DeviceId = DD.deviceId
| extend Managed = DD.isManaged
| where Compliant != "true"
| where Managed != "true"
```

Brute Force by Client App
```
SigninLogs
| where ClientAppUsed =~ "Authenticated SMTP"
| where UserPrincipalName != "annarborscan@homepointfinancial.com"
| extend LDetails = todynamic(LocationDetails)
| extend city = LDetails.city
| extend country = LDetails.countryOrRegion
| extend state = LDetails.state
| where ResultType != 0
| project UserPrincipalName,AppDisplayName,ClientAppUsed,ResourceDisplayName,IPAddress,ResultDescription,city,state,country
| summarize count() by tostring(country)
```

Successful signins using legacy apps
```
SigninLogs
| where ClientAppUsed !in ("Browser","Mobile Apps and Desktop clients")
| extend LD = todynamic(LocationDetails)
| extend city = LD.city
| extend country = LD.countryOrRegion
| extend state = LD.state
| extend DD = todynamic(DeviceDetail)
| extend dbrowser = DD.browser
| extend ddeviceid = DD.deviceId
| where ResultType == 0
| project TimeGenerated,UserPrincipalName,ResultType,AppDisplayName,ClientAppUsed,ResourceDisplayName,IPAddress,UserAgent,dbrowser,ddeviceid, ResultDescription,city,state,country
```

Get a list of Direct reports from Azure AD
```
IdentityInfo
|  summarize ['Directs']=make_set(AccountDisplayName) by Manager
```

Get principalId from AzureActivity
```
| extend PrincipalId = tostring(parse_json(tostring(parse_json(Properties).requestbody)).properties.principalId)
| extend PrincipalId_ = tostring(parse_json(tostring(parse_json(Properties).requestbody)).Properties.PrincipalId)
```

Get last device check in date
```
// query the identityinfo table, and grab the latest user record
let RiffedUsers = IdentityInfo
| where TimeGenerated > ago(30d)
| where AccountName in ("")
| summarize arg_max(TimeGenerated,*) by AccountName;
DeviceInfo
| where TimeGenerated > ago(30d)
| extend AccountName = tostring(parse_json(LoggedOnUsers[0].UserName))
| where AccountName != ""
| summarize arg_max(TimeGenerated,*) by DeviceName
| project TimeGenerated,DeviceName,JoinType,AccountName,DeviceId
| join (RiffedUsers) on AccountName
| project TimeGenerated,AccountName,AccountUPN,Department,EmployeeId,MailAddress,Manager,City,State,Phone,IsAccountEnabled
```

## Defender

Join suspicious URL to Email
```
EmailUrlInfo
| where Url contains "text/"
| join (EmailEvents
    | where Subject notcontains "[Phish Alert]")
    on NetworkMessageId
```

Network Protection logs
```
DeviceEvents 
| where ActionType in ('ExploitGuardNetworkProtectionAudited','ExploitGuardNetworkProtectionBlocked')
```

Attack Surface Reduction Audit
```
DeviceEvents 
| where ActionType startswith "asr"
```

Smartscreen logs
```
DeviceEvents
| where ActionType == "SmartScreenUrlWarning"
| extend ParsedFields=parse_json(AdditionalFields)
| project DeviceName, ActionType, Timestamp, RemoteUrl, InitiatingProcessFileName 
```

Remote SMTP connections
```
DeviceNetworkEvents
| where TimeGenerated >= ago(30d)
| where RemoteIP != "127.0.0.1"
| where ipv4_is_private(RemoteIP) == false
| where RemotePort == 25
| project DeviceName,LocalIP,LocalPort,RemoteIP,RemotePort,RemoteUrl,InitiatingProcessAccountName,InitiatingProcessCommandLine,InitiatingProcessFileName,InitiatingProcessFolderPath
```

Remote SSH and RDP connections
```
DeviceNetworkEvents
| where RemoteIP != "127.0.0.1"
| where ipv4_is_private(RemoteIP) == false
| where RemotePort == 22 or RemotePort == 3389
| where InitiatingProcessFileName !in ("Microsoft.Tri.Sensor.exe","SenseNdr.exe")
| where InitiatingProcessCommandLine !contains "string"
| where RemoteUrl !in ("domain.com")
| where RemoteIP !in ("1.2.3.4") 
| where DeviceName !in ("DeviceName")
| project TimeGenerated, DeviceName, Protocol, LocalPort, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountUpn, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessParentFileName
```

## Network

Application Gateway / Front Door Web Application Firewall logs
```
AzureDiagnostics 
| where ResourceProvider == "MICROSOFT.NETWORK" and Category == "ApplicationGatewayAccessLog"
| where ResourceProvider == "MICROSOFT.NETWORK" and Category == "FrontDoorAccessLog"
| where ResourceProvider == "MICROSOFT.NETWORK" and Category == "FrontdoorWebApplicationFirewallLog"
| where ResourceProvider == "MICROSOFT.NETWORK" and Category == "ApplicationGatewayFirewallLog"
| where host_s contains "domain.com"
| project TimeGenerated, Category, requestUri_s, ruleName_s, host_s, clientIP_s, clientPort_d, action_s, details_matches_s, details_message_s
```

Find unique RDP logons to server including device and username
```
let IPLookup = (DeviceNetworkEvents
| where LocalIP startswith "10.199"
| where InitiatingProcessAccountUpn != ""
| project InitiatingProcessAccountUpn, DeviceName, RemoteIP = LocalIP);
WireData
| where LocalIP == "10.240.8.6" or LocalIP == "40.117.186.74"
| where LocalPortNumber == "3389"
| where RemoteIP !in ("10.240.8.4","10.240.8.5","10.240.80.4","10.240.80.6")
| join (IPLookup) on RemoteIP
| distinct RemoteIP1,DeviceName,InitiatingProcessAccountUpn
```

Get a baseline and search for anomalous IPs
```
let monitoredaccounts = dynamic(["name@domain.com"]);
let knownlogins=
    SigninLogs
    | where UserPrincipalName in (monitoredaccounts)
    | where TimeGenerated > ago(14d) and TimeGenerated < ago (1d)
    | distinct IPAddress;
SigninLogs
| where TimeGenerated > ago(1d)
| where UserPrincipalName in (monitoredaccounts)
| where IPAddress !in (knownlogins)
```

## Office Activity

Search for non-company email addresses (regex)
```
AzureActivity
| where Caller matches regex @'[a-zA-Z]@[a-zA-Z]+.+[a-zA-Z]'
| where Caller !endswith "@domain.com"
```

Wide search for Office Activity
```
let name = "name";
let timeframe = ago(90d);
OfficeActivity
| where TimeGenerated >= timeframe
| where AADTarget contains name or Actor contains name or Application contains name or DestMailboxOwnerUPN contains name or LogonUserDisplayName contains name or MailboxOwnerUPN contains name or Name contains name or TargetUserId contains name or UserId contains name
```

Determine who created a new mailbox
```
let name = "mailbox name";
OfficeActivity
| where OfficeObjectId contains name
```

Scour event logs for service account activity
```
let name = "sqlsvc";
let timeframe = ago(90d);
SecurityEvent
| where TimeGenerated >= timeframe
| where Account contains name or AccountName contains name or CallerProcessName contains name or LogonID contains name or SubjectAccount contains name or SubjectUserName contains name or TargetAccount contains name or TargetUser contains name or TargetUserName contains name or UserPrincipalName contains name
| distinct Computer
```
Data uploaded to cloud
```
CloudAppEvents
| extend RawData = parse_json(RawEventData)
| extend Account = RawData.UserId
| extend Operation = RawData.Operation
| extend FileName = RawData.ObjectId
| extend DeviceName = RawData.DeviceName
| extend IPAddress = RawData.ClientIP
| extend TargetDomain = RawData.TargetDomain
| where TargetDomain !contains "company.com" 
| where Operation contains "FileUploadedToCloud"
```

## Miscellaenous

query multiple workspaces
```
union Update, workspace("contosoretail-it").Update, workspace("b459b4u5-912x-46d5-9cb1-p43069212nb4").Update
```

Count of records by day sort ascending
```
AzureActivity
| where TimeGenerated > ago(20d)
| summarize count() by Day=datetime_part("Day", TimeGenerated)
| order by Day asc
```

Search across multiple tables for device id powershell events
```
search in (DeviceEvents,DeviceProcessEvents,DeviceFileEvents) DeviceId == "xxx" and InitiatingProcessFileName contains "powershell" and InitiatingProcessCommandLine contains "Powershell"
| where InitiatingProcessParentFileName !contains "agentexecutor"
| where InitiatingProcessParentFileName !contains "senseir"
| where InitiatingProcessParentFileName !contains "AppxUpgradeUwp.exe"
```

Query Watchlist
```
_GetWatchlist('ExternalIPs')

```
