# Sample findings

These are real findings from the team's first run against the owner's own Windows PC. They're written up in text rather than screenshots, and details that could identify the machine or the owner (file paths, process IDs, network addresses, account names, and extension IDs) have been removed. Each finding follows the same format: **Severity | Evidence | False-positive assessment | Exact response command**. The specialist that finds a problem never runs the response command itself.

The fix in the first section was applied by the IDS Commander only after the owner approved it on the PC.

## IDS Commander: one incident from several specialists

Three specialists each saw part of the same problem, and the IDS Commander combined their findings into a single incident:

- **Medium, Network Monitor.** A Python script with no window was listening on all network interfaces, not just on the PC itself. Inbound firewall rules for the Python interpreter allowed any port from any address on the Public profile, and the PC was on a public Wi-Fi network at the time. The script had no outbound connections. It was probably the owner's own project, but anyone on the same network could reach it if it had no authentication.
- **Low, Process Monitor.** The same script was running from the Downloads folder with no console window and had started about three minutes after boot, which pointed to an autostart entry.
- **High, Startup Monitor.** It found the launcher: a small batch file in the owner's Startup folder, created months earlier by the owner's own account. It was rated High because it starts a hidden, unsigned interpreter from Downloads that listens on all interfaces and has a Public firewall rule.
- **IDS Commander.** It sent the owner one incident and proposed removing the broad firewall rules. The owner approved the fix on the PC, and the rules were removed after a backup was taken.

## Windows Log Monitor: Defender, logs, and PowerShell

- **Info, Defender healthy.** No detections in the last 30 days. Real-time protection, behavior monitoring, and Tamper Protection were all on, signatures were current, and the configuration changes in the log were routine. No real-time protection or tamper changes were logged. (The exclusion list itself can't be read without admin rights.)
- **Low, high-volume hidden PowerShell sessions.** More than 2,000 non-interactive PowerShell sessions had started in the previous day, each with commands piped in rather than typed. The pattern matched AI coding-agent and editor terminal tooling that was active at the same times, and the sessions were ruled benign. Under the team's rules, a PowerShell session only counts as the team's own if it appears in one of the team's command logs.
- **Low, visibility gap.** The Security log and audit policy couldn't be read without admin rights, so logon, account, scheduled task, and log-clearing checks were reported as not covered rather than as clean.
- **Info, antivirus service churn.** Repeated service installs from the installed antivirus suite, all with valid vendor signatures. This is normal behavior for that product.
- **Info, no System log clearing.** No event showed the System log being cleared.

## Network Monitor: remote access and network settings

- **Info, remote access is off.** Remote Desktop was disabled with nothing listening on its port. The OpenSSH server wasn't installed, WinRM was stopped, and no VNC or remote-support tools were running. Inbound SMB was blocked on the Public profile, and only the default Windows shares existed.
- **Info, firewall, proxy, hosts file, and Tor.** All three firewall profiles were on and blocked inbound traffic by default. No proxy was set anywhere. The hosts file held only entries added by a container tool. No Tor processes or Tor ports were found. Firewall logging was off, and turning it on was proposed.
- **Low, stale per-app firewall rules.** Many inbound allow rules had been created over time by clicking "Allow" at prompts, including some for programs in temporary and scratch folders. Stale rules like these would let any later program at the same path through. The proposed response disables the stale Temp-folder rules.
- **Low, idle VPN service listening.** An installed peer-to-peer VPN service was listening on all interfaces and allowed on all profiles, but no VPN network was joined. The proposed response is to set it to manual start if it isn't used.
- **Low (privacy), AI desktop app.** An AI assistant app was running unsigned from a temporary folder and had outbound HTTPS connections to cloud providers, but it accepted no incoming connections. Nothing pointed to malware.
- **Info, local AI model server.** A local LLM server was listening on the PC itself only, not on the network.

## Process Monitor: running processes

- **No High findings.** No system process name was running from outside its normal folder, service host parents were normal, there was a single copy of the Windows login process, and there was no encoded or hidden PowerShell, no Office app spawning shells, and no built-in Windows tools (LOLBins) being abused.
- **Medium, unverified app from Downloads.** A portable AI desktop app launched from Downloads had unpacked itself into a temporary folder and was running from there. That's typical for portable apps of that kind, but the owner was asked to confirm it was run on purpose and to check its signature and hash.
- **Info, known tools added to the baseline.** A local LLM server, a local MCP server started by a code editor, a VPN client, hardware vendor utilities, and the team's own baseline command were confirmed as expected.

## Startup Monitor: autostarts and browser extensions

- **Medium, browser extensions with broad permissions (under review).** Several browser extensions had high-risk permissions, such as debugger access, proxy and extension management, or access to every site. Most looked like AI and automation tools the owner installed, but the debugger permission gives full control of a page, including cookies and sessions. The extensions whose names couldn't be resolved are the priority to identify. They're still under review with the owner.
- **Low, leftover service.** A service left behind by an incomplete antivirus uninstall was set to start automatically but pointed to a missing file. The risk is low because that folder needs admin rights to write to.
- **Low, unsigned binaries in autostarts.** Most were likely false positives. Store-packaged apps and built-in drivers are catalog-signed, and the signature check only sees embedded signatures, so they show up as unsigned.
- **Low, browser with a broad footprint.** A signed third-party browser had set itself to autostart and added an extension to another browser. It's fine to keep if the owner installed it on purpose.
