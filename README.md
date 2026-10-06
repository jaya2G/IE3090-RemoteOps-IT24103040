# IE3090 RemoteOps

## Student Information

Registration Number: IT24103040

Module: IE3090 - Network Programming

Assignment: RemoteOps - A Remote System Monitoring and Management Tool over TCP/IP

## Testing Evidence

The system was tested using the following scenarios:

1. Successful authentication.
2. Failed authentication.
3. SYSINFO.
4. LISTPROC.
5. All five permitted EXEC commands.
6. Rejection of a non-whitelisted EXEC command.
7. PUT file upload.
8. GET file download.
9. Byte-for-byte file comparison using cmp and SHA-256.
10. UDP monitoring.
11. UDP monitoring stop.
12. Graceful QUIT.
13. Multiple simultaneous Controller connections.
14. Log generation.

## Verification Commands

Check listening TCP port:

```bash
ss -tlnp | grep 9410

