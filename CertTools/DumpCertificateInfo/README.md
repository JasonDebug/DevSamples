# DumpCertificateInfo

`DumpCertificateInfo` is a .NET diagnostic tool that inspects a certificate (typically from a file or remote TLS connection) and performs deep validation using Windows' certificate chain engine. It provides insight into the certificate’s trust chain, revocation status, and catalog signature presence.


## Features

- Loads a certificate from a `.cer` or `.crt` file
- Builds and displays the certificate chain using Windows CryptoAPI
- Checks revocation status (CRL/OCSP)
- Attempts to locate associated Windows catalog files
- Displays certificate properties:
  - Subject / Issuer
  - Thumbprint
  - Validity period
  - Signature algorithm
- Logs any issues in the chain (e.g., expired or untrusted certs)
- Detects if the certificate is part of a Windows catalog (driver signing)


## Usage

DumpCertificateInfo.exe path\to\cert.cer
