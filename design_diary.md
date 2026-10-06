# RemoteOps Design Diary

## 4 October 2026

### Initial Setup

Created the RemoteOps GitHub repository and prepared the CentOS development environment inside VirtualBox.

Calculated the personalised assignment values from registration number IT24103040:

- TCP port: 9410
- SID: 0403
- Authentication token: OPS-3040
- Source suffix: 040
- Log file: remoteops_IT24103040.log
- Storage path: ./agentfiles/IT24103040/

### Architecture Decision

I selected a threaded concurrency model for the Agent. Each incoming TCP Controller connection is handled by a separate POSIX thread.

I selected this approach because it is relatively simple to implement and allows several Controllers to communicate with one Agent simultaneously.

### Protocol Decision

I followed the line-based TCP protocol given in the assignment instead of designing a custom protocol.

The Agent uses a line reader for commands and exact byte counting for PUT and GET.

### System Information

Linux /proc files are used to obtain system information:

- /proc/loadavg
- /proc/meminfo
- /proc/uptime

### Security Decision

EXEC is restricted to the five commands specified by the assignment:

- DATE
- UPTIME
- DISKFREE
- HOSTNAME
- WHOAMI

Arbitrary shell commands are rejected.

### File Transfer

PUT stores uploaded files under the personalised agentfiles directory.

GET reads the stored file and sends the exact file size to the Controller.

### UDP Monitoring

UDP monitoring was implemented using a separate monitoring thread for each session. The Agent periodically sends SYSINFO statistics to the Controller's selected UDP port.

### Testing

Tested:

- Authentication
- SYSINFO
- LISTPROC
- EXEC whitelist
- PUT
- GET
- UDP monitoring
- QUIT
- Logging
- Multiple Controller connections
