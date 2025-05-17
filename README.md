# Lsass-monitor
Windows tool that enumerates all open handles in the system and identifies which processes hold handles to the LSASS process (`lsass.exe`)

1. Enables SeDebugPrivilege
 Grants the program high-level access to system processes (including protected ones like LSASS).

2. Finds the PID of `lsass.exe`
LSASS (Local Security Authority Subsystem Service) is a critical Windows process that manages user credentials.

3. Enumerates all system handles
Uses `NtQuerySystemInformation(SystemHandleInformation)` to retrieve a list of all open handles on the system.

4. Duplicates handles from each process
For each handle, attempts to duplicate it into its own process using `DuplicateHandle`.
If the duplicated handle is a process handle and maps back to LSASS, it logs that.

5. Logs processes with LSASS handles
Records and prints any process ID, process name, and handle value that points to LSASS.

6. Runs continuously
   Keeps checking every second, creating a near-real-time monitor for LSASS access.

🎯 Use Cases by Audience

🔴 Red Team:

 Target Recon: Helps identify which processes already have handles to LSASS, possibly avoiding redundant injection or detection.
 Stealth Verification: Can confirm whether your malware/tool has successfully obtained a handle to LSASS.
 Living-off-the-Land Bypass: Can be used to “piggyback” on processes that already have LSASS handles, minimizing your own footprint.

🛡️ Blue Team / Defenders:

 Detection of LSASS access:
  Continuous logging allows defenders to detect unauthorized or unexpected processes accessing LSASS—one of the most common goals in credential dumping attacks.
 Forensic evidence:
  Output can be used in incident response or memory analysis to identify which processes interacted with sensitive system components.
 Honeypot trap:
  Can be adapted to monitor bait LSASS processes or detect mimicry attacks.

🔬 Security Researchers:

 Windows internals research:
  
 Handle management:
  Useful for studying how different tools interact with LSASS (e.g., antivirus, credential dumping tools, EDRs).
 Comparative tool testing:
  Can help researchers measure which tools open LSASS handles and when.

---

⚠️ Limitations and Notes

 Must be run as Administrator
