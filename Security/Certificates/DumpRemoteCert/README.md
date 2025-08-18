## DumpRemoteCert

This sample demonstrates some basic certificate functions.  The main purpose of this sample is to display certificate information from a given endpoint, whether the certificate is valid or not.

### Usage

`DumpRemoteCert.exe <endpoint[:port]> [port] [--ForceProtocolVersion *SslProtocols*}]

Examples:
- `DumpRemoteCert.exe example.com:443`
- `DumpRemoteCert.exe example.com 443 -ForceProtocolVersion Tls12,Tls13`

If no port is specified, 443 will be used as a default.

### More Info

[SslStream Class](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream?view=net-8.0)
[SslProtocols Enum](https://learn.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols?view=net-8.0)
[TcpClient Class](https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient?view=net-8.0)
[X509Certificate2 Class](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2?view=net-8.0)
[certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)