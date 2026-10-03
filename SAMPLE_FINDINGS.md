# Sample findings

These are real findings from the team's first run on the owner's own Windows PC on September 29, 2026. Details that could identify the machine or the owner have been removed. That covers names, file paths, process IDs, network addresses, extension IDs, and anything about the decoys.

Findings travel in two steps:

1. **Specialist reports.** Each specialist reports every finding to the IDS Commander with four fields: **Severity**, **Evidence**, **False-positive assessment**, and **Response command**. A specialist never runs the response command itself.
2. **One summary for the owner.** The IDS Commander combines related findings into incidents and sends the owner one message with a bold severity header for each section and short bullets under it.

The summary comes first below, because that is what the owner actually reads. The specialist reports behind it follow. Commands use placeholders such as `<service-name>` in place of real paths and names.

## What the owner receives: the IDS Commander's summary

The original message wasn't saved, so this is the same summary format rebuilt from the first run's real findings.

> **🔴 Critical**
> - None.
>
> **🟠 High/Medium**
> - A hidden Python script started from Downloads at login and was listening on all network interfaces. Two broad inbound firewall rules for that Python program allowed it on the Public profile, and the PC was on public Wi-Fi. It is probably your own project. Proposed fix: delete those two firewall rules after taking a backup.
> - Browser extensions with high-risk permissions (debugger access, proxy and extension management, or access to every site). Two have names that couldn't be resolved. Please confirm which ones you installed.
> - An AI desktop app launched from Downloads unpacked itself into a temporary folder and is running from there. Please confirm you ran it on purpose.
> - Unsigned installers downloaded from the internet are sitting in Downloads. Hash lookups are recommended.
>
> **🟡 Low**
> - About 2,000 non-interactive PowerShell sessions in one day, most likely from AI coding or editor tools. Please confirm which tool starts them.
> - Many old per-app inbound firewall rules, some for programs in temporary and scratch folders.
> - An idle peer-to-peer VPN service is listening on all interfaces.
> - The AI desktop app sends data to cloud services (privacy note).
> - An installed AI assistant is unsigned and has computer-use features (rated Low-Medium). Unsigned keyboard and mouse hook libraries are in Temp.
> - A leftover antivirus service points to a missing file, a browser autostarts and added an extension to another browser, and some autostart programs show as unsigned (mostly false positives).
> - Coverage gaps: the Security log and audit policy can't be read without admin rights, and the AI-agent layer wasn't checked because AI Agent Monitor's baseline didn't run.
>
> **✅ Clear**
> - Defender: healthy, no detections in 30 days, no tampering.
> - Remote access: off. Firewall on for all profiles, no proxy, no Tor, hosts file normal.
> - Processes: no disguised system processes, no encoded PowerShell, no misused built-in tools.
> - Files: no PowerShell profiles, no SSH server or authorized keys, system files signed, no ransomware signs.
> - Decoys: no touches.

## IDS Commander: one incident from several specialists

Five specialists each reported part of the same problem. In the summary above, they appear as one item.

- **Network Monitor (Medium)** found the script listening on all interfaces, with broad inbound rules for its Python program on the Public profile.
- **Process Monitor (Low)** found the same script running from Downloads with no window, starting about three minutes after boot, which pointed to an autostart entry.
- **Startup Monitor (High)** found the launcher, a small batch file in the owner's Startup folder.
- **Windows Log Monitor (Low)** flagged the same startup script as a hygiene issue.
- **File Change Monitor (Low-Medium)** later reviewed the script's code and found no keylogging, screen capture, credential theft, or obfuscation.

**What happened next:**

- The owner approved the fix on the PC.
- The IDS Commander backed up the two broad inbound firewall rules for that Python program on the Public profile, then deleted them.
- Network Monitor now treats any return of a rule like this as Medium.
- With the owner's approval, the IDS Commander also stopped one of Network Monitor's own collection commands, which had hung.
- Network Monitor's later scheduled rechecks couldn't confirm the fix because the PC was offline.

## Network Monitor: listening ports, connections, and firewall

### Medium: script listening on all interfaces, allowed through the firewall on Public

- **Severity:** Medium
- **Evidence:** A windowless Python script started from Downloads was listening on all network interfaces, not just on the PC itself. Two enabled inbound allow rules for that Python program (one TCP, one UDP) allowed any port from any address on the Public profile. They had been created when someone clicked "Allow" at a Windows prompt. The PC was on public Wi-Fi. The Python program itself was validly signed. The script had no outbound connections.
- **False-positive assessment:** Probably the owner's own project, but anyone on the same network could reach it if it has no authentication.
- **Response command:** Best fix is to make the script listen on the PC itself (localhost) only. Firewall fix proposed (admin): `Get-NetFirewallApplicationFilter -Program '<path-to-pythonw.exe>' | Get-NetFirewallRule | Where-Object {$_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'} | Disable-NetFirewallRule`. The fix actually applied after the owner approved it was a backup followed by deleting the two rules (see the IDS Commander section).

### Low: stale per-app inbound firewall rules

- **Severity:** Low
- **Evidence:** 265 enabled inbound allow rules. Many allowed any port from any address on the Public profile and were created by clicking "Allow" at prompts over time. Some were for programs in temporary and scratch folders. This includes broad Public rules for the regular Python program, which weren't part of the approved fix.
- **False-positive assessment:** This is the normal result of clicking "Allow". The risk is that a stale rule lets any later program at the same path through.
- **Response command:** Review first: `Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object DisplayName -match '<app-name-pattern>' | Format-Table DisplayName,Profile`. Then disable the stale Temp-folder rules (admin): `Get-NetFirewallApplicationFilter | Where-Object Program -like '*\appdata\local\temp\*' | Get-NetFirewallRule | Disable-NetFirewallRule`

### Low: idle peer-to-peer VPN service listening

- **Severity:** Low
- **Evidence:** An installed peer-to-peer VPN service was listening on all interfaces and allowed on all profiles. No VPN network was joined.
- **False-positive assessment:** Harmless while no network is joined, but it would become a remote-access path if one were.
- **Response command:** If it isn't used: `Stop-Service <vpn-service-name>; Set-Service <vpn-service-name> -StartupType Manual`

### Low (privacy): AI desktop app with outbound connections

- **Severity:** Low (privacy)
- **Evidence:** An AI assistant app was running unsigned from a temporary folder, with two outbound HTTPS connections to cloud providers. It had no listening ports.
- **False-positive assessment:** Unsigned unpacking into Temp is normal for this kind of portable app, and nothing pointed to malware. It is an app that records audio and sends data to the cloud.
- **Response command:** `Get-Process '<app-name>' | Stop-Process`

### Info: checks that came back clean

- **Severity:** Info
- **Evidence:**
  - Remote Desktop was off with nothing listening on its port. No OpenSSH server was installed, WinRM was stopped, and no VNC or remote-support tools were found. Inbound SMB was blocked on Public, and only the default Windows shares existed.
  - All three firewall profiles were on and blocked inbound traffic by default. Firewall logging was off.
  - No proxy was set anywhere. The hosts file held only entries written by a container tool. No Tor processes or ports.
  - A local AI model server listened on the PC itself only.
  - A local MCP server started by a code editor had no listening port.
  - Outbound connections went to well-known cloud, developer, and app services. DNS looked normal.
- **False-positive assessment:** Not applicable. These are expected results.
- **Response command:** Optional, to turn on firewall logging (admin): `Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384`

## Process Monitor: running processes

### Medium: unverified AI desktop app running from a temporary folder

- **Severity:** Medium
- **Evidence:** A portable AI desktop app launched from Downloads unpacked itself into a temporary folder. It was running six processes from there, including an audio capture service and a network service without a sandbox.
- **False-positive assessment:** Typical of portable apps of this kind, but it is an unverified program from Downloads running out of Temp. File Change Monitor later found that the installer had a valid signature and the unpacked app was unsigned.
- **Response command:** None proposed. Owner to confirm it was run on purpose, and to check its signature and hash.

### Low: hidden Python script from Downloads started at login

- **Severity:** Low
- **Evidence:** Python with no window, running a script from Downloads, started about three minutes after boot.
- **False-positive assessment:** Likely the owner's own project. Startup Monitor was asked to confirm the autostart entry.
- **Response command:** None proposed. Passed to Startup Monitor.

### Info: no High findings, known tools added to the baseline

- **Severity:** Info
- **Evidence:**
  - No system process name ran from outside its normal folder.
  - Service host parents were normal, and there was a single copy of the Local Security Authority process (lsass), which handles sign-ins.
  - No encoded or hidden PowerShell running at the time of the snapshot, no Office app starting shells, and no misused built-in Windows tools (LOLBins).
  - On this first run, the bot judged these tools benign and added them to its baseline: a local AI model server, a local MCP server started by a code editor, a Python test script started by an AI assistant app, a browser updater, a VPN client, hardware vendor utilities, an antivirus firewall component, and the team's own baseline command.
- **False-positive assessment:** These were the bot's own judgment. The owner hadn't confirmed them yet.
- **Response command:** None needed.

## Startup Monitor: autostarts and browser extensions

### High: Startup-folder batch file launches the hidden Python script

- **Severity:** High
- **Evidence:**
  - A small batch file in the owner's Startup folder runs Python with no window on a script in Downloads. Its start time matched the running script.
  - The file was created locally about four months earlier and is owned by the owner's account. It wasn't marked as downloaded.
  - No other autostart entry referenced it.
- **False-positive assessment:** Possibly the owner's own project. It was rated High until the owner confirms, because it runs a hidden, unsigned script from Downloads that listens on all interfaces, and Python had Public firewall rules allowing every inbound port.
- **Response command:**
  - Stop the running script: `Stop-Process -Id <pid>`
  - Disable the autostart (reversible): `New-Item -ItemType Directory -Force "$env:USERPROFILE\quarantine" | Out-Null; Move-Item -LiteralPath "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\<launcher>.bat" -Destination "$env:USERPROFILE\quarantine\<launcher>.bat.txt"`
  - Delete the firewall rules (admin): `Remove-NetFirewallRule -Name '<tcp-rule-name>','<udp-rule-name>'`
  - Only the firewall step was applied, after the owner approved it.

### Medium: browser extensions with high-risk permissions

- **Severity:** Medium
- **Evidence:** Several extensions had high-risk permissions such as debugger access, proxy and extension management, or access to every site. Two extensions whose names couldn't be resolved had proxy and extension management permissions.
- **False-positive assessment:** Most are probably AI and automation tools the owner installed. The debugger permission gives full control of a page, including cookies and sessions. The two unnamed extensions are the priority to identify.
- **Response command:** Owner to confirm. To remove one, use the browser's extensions page. With the browser closed, the file-level equivalent is `Remove-Item -Recurse -LiteralPath "<browser-profile>\Extensions\<extension-id>"`

### Low: browser with a broad footprint

- **Severity:** Low
- **Evidence:** A signed third-party browser had set itself to autostart, added update services, and added an extension to another browser.
- **False-positive assessment:** It behaves like a normal install. Fine to keep if the owner installed it on purpose.
- **Response command:** `Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name '<autostart-name>'`, or uninstall it in Settings.

### Low: leftover service pointing to a missing file

- **Severity:** Low
- **Evidence:** A service left behind by an antivirus vendor's component was set to start automatically, but its program file didn't exist.
- **False-positive assessment:** Most likely left over from an incomplete uninstall. A program planted at that path would run with full system rights, but the folder needs admin rights to write to, so the risk is low.
- **Response command:** Admin: `sc.exe delete "<service-name>"`

### Low: unsigned programs in autostarts

- **Severity:** Low
- **Evidence:** A few autostart entries pointed to programs that showed as unsigned: a Store-packaged graphics service, a built-in app, a built-in driver, and an AI code editor installed in the user's app folder.
- **False-positive assessment:** Mostly false positives. Store apps and built-in drivers are catalog-signed, and the check only sees embedded signatures. The code editor is the one worth checking by hash.
- **Response command:** None until the hashes are checked.

### Info: checks that came back clean

- **Severity:** Info
- **Evidence:**
  - No autostart entry launches PowerShell, so the non-interactive PowerShell sessions don't come from a startup entry.
  - No autostart for the AI desktop app or the local MCP server.
  - WMI, Winlogon, and other common hijack points were at Windows defaults.
  - Other autostart entries added or updated in the last 30 days came from known vendors and looked like normal app updates.
- **False-positive assessment:** Not applicable.
- **Response command:** None needed.

## Windows Log Monitor: Defender, logs, and PowerShell

### Low: visibility gap

- **Severity:** Low
- **Evidence:** The Security log and audit policy couldn't be read without admin rights, so logon, account change, and log-clearing checks weren't covered. The Task Scheduler log was turned off, and PowerShell script block logging appeared to be off. The Defender exclusion list needs admin rights to read.
- **False-positive assessment:** Not a threat. These areas are reported as not covered rather than as clean.
- **Response command:** None proposed. Owner to decide whether to rerun from an admin session or add the account to Event Log Readers, and whether to turn on script block logging, the Task Scheduler log, and logon, account, and process-creation auditing.

### Low: high volume of non-interactive PowerShell sessions

- **Severity:** Low
- **Evidence:** 2,047 PowerShell starts in the 24 hours reviewed. 2,012 were non-interactive sessions with commands piped in rather than typed. The parent program isn't logged.
- **False-positive assessment:** Likely a false positive. The pattern matches AI coding-agent and editor terminal tools, and developer activity was happening at the same times. Needs the owner's confirmation.
- **Response command:** None proposed. Owner to confirm which tool starts these sessions.

### Low: startup script runs code from Downloads

- **Severity:** Low
- **Evidence:** The same Startup-folder batch file and hidden Python script that Startup Monitor found.
- **False-positive assessment:** Most likely created by the owner and legitimate. The risk is that it runs from Downloads with no window.
- **Response command:** None proposed. Suggested moving the project out of Downloads and launching it from a fixed project folder.

### Info: Defender healthy

- **Severity:** Info
- **Evidence:**
  - No detections in the last 30 days.
  - Real-time protection, behavior monitoring, and Tamper Protection were on, and signatures were current.
  - The 27 configuration changes in the log were routine settings and cloud feature updates, with no exclusion, real-time protection, or tamper changes.
- **False-positive assessment:** Not applicable.
- **Response command:** None needed.

### Info: other log results

- **Severity:** Info
- **Evidence:**
  - Antivirus service churn: 21 service installs from the installed antivirus suite, each set to disabled afterward. The main program had a valid vendor signature.
  - No event showed the System log being cleared.
  - Script blocks had no download-and-run or antivirus-bypass code. One process listing at the start of the run matches Process Monitor's logged baseline command at the same second.
  - Developer activity: a public (anon) web API key appeared on a command line and is now stored in plain text in the PowerShell log. Keys of this type are public by design.
  - A few extra local accounts look like AI-agent sandbox accounts and existed before the window reviewed.
  - System errors included Windows Update install failures.
- **False-positive assessment:** Benign or routine.
- **Response command:** None proposed. Owner to confirm the sandbox accounts are still needed and to look into the update failures.

## File Change Monitor: file fingerprints and new files

This first pass recorded 95,603 files, so there was nothing yet to compare against. These findings come from that baseline.

### Medium: unsigned installers from the internet in Downloads

- **Severity:** Medium
- **Evidence:** Several unsigned installers marked as downloaded from the internet, all from code-hosting release pages, were sitting in Downloads.
- **False-positive assessment:** Small open-source desktop apps are often unsigned, and the owner downloaded these.
- **Response command:** None proposed. Hash lookups (for example on VirusTotal) recommended.

### Low-Medium: startup script runs code from Downloads with no window

- **Severity:** Low-Medium (the bot's own rating)
- **Evidence:**
  - The same Startup-folder batch file. It matches what the project's own setup script writes.
  - A read-only review of the project's code found no keylogging, screen or clipboard capture, credential-store access, or obfuscation.
  - Its code makes threat-intelligence lookups, sends email alerts, checks an AI service's API billing, and serves a web dashboard (which Network Monitor found listening on all interfaces).
  - Its config file, which wasn't read, likely holds API keys and email credentials in plain text.
- **False-positive assessment:** Looks like the owner's own security project. The risk is running code from a user-writable folder, plus plain-text credentials.
- **Response command:** None proposed. Owner to confirm.

### Low-Medium: unsigned AI assistant with computer-use features

- **Severity:** Low-Medium (the bot's own rating)
- **Evidence:** An installed AI assistant app was unsigned and included computer-use and hardware input components.
- **False-positive assessment:** A user-installed AI assistant. Those features are part of what this kind of app does.
- **Response command:** None proposed. Owner to review.

### Low: keyboard and mouse hook libraries in Temp

- **Severity:** Low
- **Evidence:** Unsigned global input-hook libraries were in Temp. The data didn't show which app put them there.
- **False-positive assessment:** This library is common in Java desktop apps for global hotkeys, but it can also be used for keylogging.
- **Response command:** None proposed.

### Low: unsigned app unpacked into Temp from a signed installer

- **Severity:** Low
- **Evidence:** The AI desktop app that Process Monitor flagged. Its installer had a valid signature, and the files unpacked into Temp were unsigned.
- **False-positive assessment:** Normal for this packaging style.
- **Response command:** None proposed.

### Info: checks that came back clean

- **Severity:** Info
- **Evidence:**
  - The hosts file had only container-tool entries.
  - No SSH server and no authorized keys.
  - No PowerShell profiles, and no command-prompt AutoRun entry.
  - All top-level system programs and all but one driver were validly signed. The one exception is a built-in Bluetooth driver, likely a catalog-signing false positive.
  - No ransom notes or ransomware file extensions.
  - Red-team testing modules sat in Downloads, likely from the owner's own coursework.
  - The team's own command scripts were in Temp.
- **False-positive assessment:** Not applicable.
- **Response command:** None needed.

## Decoy Monitor: decoys

The Decoy Monitor planted its decoys on the same day as the first run, after the owner approved the exact plan. No decoy touches were recorded.

### Info: teammate scan recorded as team activity

- **Severity:** Info
- **Evidence:** File Change Monitor's baseline scan read one decoy file at two times. Both matched File Change Monitor's own command log.
- **False-positive assessment:** Not a touch. It was recorded as team activity. The scanner's decoy skip list had missed that file, and File Change Monitor's scanner was updated to skip it.
- **Response command:** None needed.

## AI Agent Monitor: AI-agent layer

AI Agent Monitor's live baseline didn't run on the first run, so it has no findings yet.
