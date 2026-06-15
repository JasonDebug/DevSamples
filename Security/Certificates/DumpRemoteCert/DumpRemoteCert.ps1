##################################################################################
# MIT License                                                                    #
#                                                                                #
# Copyright (c) JasonDebug                                                       #
#                                                                                #
# Permission is hereby granted, free of charge, to any person obtaining a copy   #
# of this software and associated documentation files (the "Software"), to deal  #
# in the Software without restriction, including without limitation the rights   #
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      #
# copies of the Software, and to permit persons to whom the Software is          #
# furnished to do so, subject to the following conditions:                       #
#                                                                                #
# The above copyright notice and this permission notice shall be included in all #
# copies or substantial portions of the Software.                                #
#                                                                                #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     #
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       #
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    #
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         #
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  #
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  #
# SOFTWARE.                                                                      #
##################################################################################
Param
(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Endpoint,

    [Parameter(Mandatory=$false, Position=1)]
    [int]$Port = 443,

    [string]$CertOutputFile,
    [string]$LogToFile,
    [switch]$SkipCertPopup,
    
    ## Forces a specific TLS/SSL protocol version. When omitted, the system-default protocol selection is used.
    ## https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream.authenticateasclient
    ## https://learn.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols
    ## Note regarding "Default" setting -- Despite the name of this field, SslStream does not use it as a default except
    ## under special circumstances, and is considered obsolete. Use "None" to allow the OS to choose, but that's inconsistent.
    [System.Security.Authentication.SslProtocols]$Protocols = [System.Security.Authentication.SslProtocols]::Tls12
)

Process
{
    # If no protocol passed, default to Tls12, Tls13 due to some PS instance config issues
    if (!($PSBoundParameters.ContainsKey('Protocols')) -and
        [Enum]::IsDefined([System.Security.Authentication.SslProtocols], 'Tls13'))
    {
        $Protocols -bor [System.Security.Authentication.SslProtocols]::Tls13
    }

    if ($LogToFile) {
        Start-Transcript -Path $LogToFile
    }

    Write-Host "Running:" -ForegroundColor Yellow
    Write-Host "  $($MyInvocation.Line)"
    Write-Host
    
    $dumpCertInfo = [System.Net.Security.RemoteCertificateValidationCallback]{
        param($sender, $certificate, $chain, $errors)

        if (!($CertOutputFile)) {
            $CertOutputFile = [System.IO.Path]::GetTempFileName().Replace(".tmp", ".cer")
        } else {
            $CertOutputFile = [System.IO.Path]::GetFullPath($CertOutputFile)
        }

        $x509 = $certificate -as [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $bytes = $x509.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [System.IO.File]::WriteAllBytes($CertOutputFile, $bytes)

        Write-Host "Certificate written to: $CertOutputFile"
        Write-Host

        # At-a-glance info
        Write-Host "Quick Info:" -ForegroundColor Yellow
        Write-Host "Subject: $($x509.Subject)"
        Write-Host "Issuer: $($x509.Issuer)"
        Write-Host "Validity period: $($x509.NotBefore) to $($x509.NotAfter)"

        $sanExtension = $x509.Extensions["2.5.29.17"]
        if ($sanExtension -ne $null) 
        {
            $sanData = New-Object System.Security.Cryptography.AsnEncodedData -ArgumentList $sanExtension.Oid, $sanExtension.RawData
            $sanStrings = $sanData.Format($true)

            Write-Host "Subject alternative names (SAN):"
            Write-Host $sanStrings.Replace([Environment]::NewLine, [Environment]::NewLine + "  ")
        }

        Write-Host "Policy Errors: " -NoNewline
        if ($errors -eq [System.Net.Security.SslPolicyErrors]::None)
        {
            Write-Host $errors -ForegroundColor Green
        }
        else
        {
            Write-Host $errors -ForegroundColor Red
        }
        Write-Host

        Write-Host "Running:" -ForegroundColor Yellow
        Write-Host "  certutil -urlfetch -verify `"$CertOutputFile`""
        Write-Host

        ## Start-Process output does not display correctly
        ## Export to file and read it in and we'll have broken newlines
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.CreateNoWindow = $true
        $ProcessInfo.FileName = "certutil.exe"
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.Arguments = "-urlfetch -verify `"$CertOutputFile`""
    
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start()
    
        $output = $Process.StandardOutput.ReadToEnd()

        $Process.WaitForExit()

        Write-Host $output

        if (!($SkipCertPopup.IsPresent)) {
            Start-Process $CertOutputFile
        }

        $true
    }

    Write-Host "Connecting to '$Endpoint' on port $Port..." -ForegroundColor Yellow
    
    $error.Clear()
    try
    {
        $client = New-Object System.Net.Sockets.TcpClient -ArgumentList $Endpoint, $Port
        $ssl = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false, $dumpCertInfo

        if ($Protocols -eq [System.Security.Authentication.SslProtocols]::None)
        {
            # On some systems, 'None' fails with a param error due to PowerShell session configuration (DisableSystemDefaultTlsVersions)
            # https://github.com/microsoft/referencesource/blob/ec9fa9ae770d522a5b5f0607898044b7478574a3/System/net/System/Net/SecureProtocols/_SslState.cs#L164
            # This is generally a problem in older OSes such as Server 2019, or in the ISE PowerShell terminal.

            Write-Host "Using protocol: " -NoNewline
            Write-Host "None (OS chooses)" -ForegroundColor Cyan
            $ssl.AuthenticateAsClient($Endpoint, $null, $true)
        }
        else
        {
            Write-Host "Using protocol(s): " -NoNewline
            Write-Host $Protocols -ForegroundColor Cyan
            $ssl.AuthenticateAsClient($Endpoint, $null, $Protocols, $true)
        }

        Write-Host "Negotiated protocol: " -ForegroundColor Yellow -NoNewline
        Write-Host $ssl.SslProtocol
    }
    catch
    {
        Write-Host
        Write-Host "Connection error:" -ForegroundColor Red


        if ($DebugPreference)
        {
            Write-Host "$($error.FullyQualifiedErrorId) : $($error.Exception.ToString())"
        }
        else
        {
            Write-Host "$($error.FullyQualifiedErrorId) : $error"
        }

        Write-Host
    }
    finally
    {
        $ssl.Close()
        $client.Close()
        
        if ($LogToFile) {
            Stop-Transcript
        }
    }
}

# SIG # Begin signature block
# MII9QAYJKoZIhvcNAQcCoII9MTCCPS0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBVwRcF5kqrJWFg
# xTQj5FO48YYUoCjpl5+/608FENlrlaCCIgIwggXMMIIDtKADAgECAhBUmNLR1FsZ
# lUgTecgRwIeZMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVu
# dGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAy
# MDAeFw0yMDA0MTYxODM2MTZaFw00NTA0MTYxODQ0NDBaMHcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jv
# c29mdCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALORKgeD
# Bmf9np3gx8C3pOZCBH8Ppttf+9Va10Wg+3cL8IDzpm1aTXlT2KCGhFdFIMeiVPvH
# or+Kx24186IVxC9O40qFlkkN/76Z2BT2vCcH7kKbK/ULkgbk/WkTZaiRcvKYhOuD
# PQ7k13ESSCHLDe32R0m3m/nJxxe2hE//uKya13NnSYXjhr03QNAlhtTetcJtYmrV
# qXi8LW9J+eVsFBT9FMfTZRY33stuvF4pjf1imxUs1gXmuYkyM6Nix9fWUmcIxC70
# ViueC4fM7Ke0pqrrBc0ZV6U6CwQnHJFnni1iLS8evtrAIMsEGcoz+4m+mOJyoHI1
# vnnhnINv5G0Xb5DzPQCGdTiO0OBJmrvb0/gwytVXiGhNctO/bX9x2P29Da6SZEi3
# W295JrXNm5UhhNHvDzI9e1eM80UHTHzgXhgONXaLbZ7LNnSrBfjgc10yVpRnlyUK
# xjU9lJfnwUSLgP3B+PR0GeUw9gb7IVc+BhyLaxWGJ0l7gpPKWeh1R+g/OPTHU3mg
# trTiXFHvvV84wRPmeAyVWi7FQFkozA8kwOy6CXcjmTimthzax7ogttc32H83rwjj
# O3HbbnMbfZlysOSGM1l0tRYAe1BtxoYT2v3EOYI9JACaYNq6lMAFUSw0rFCZE4e7
# swWAsk0wAly4JoNdtGNz764jlU9gKL431VulAgMBAAGjVDBSMA4GA1UdDwEB/wQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIftJqhSobyhmYBAcnz1AQ
# T2ioojAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEAr2rd5hnn
# LZRDGU7L6VCVZKUDkQKL4jaAOxWiUsIWGbZqWl10QzD0m/9gdAmxIR6QFm3FJI9c
# Zohj9E/MffISTEAQiwGf2qnIrvKVG8+dBetJPnSgaFvlVixlHIJ+U9pW2UYXeZJF
# xBA2CFIpF8svpvJ+1Gkkih6PsHMNzBxKq7Kq7aeRYwFkIqgyuH4yKLNncy2RtNwx
# AQv3Rwqm8ddK7VZgxCwIo3tAsLx0J1KH1r6I3TeKiW5niB31yV2g/rarOoDXGpc8
# FzYiQR6sTdWD5jw4vU8w6VSp07YEwzJ2YbuwGMUrGLPAgNW3lbBeUU0i/OxYqujY
# lLSlLu2S3ucYfCFX3VVj979tzR/SpncocMfiWzpbCNJbTsgAlrPhgzavhgplXHT2
# 6ux6anSg8Evu75SjrFDyh+3XOjCDyft9V77l4/hByuVkrrOj7FjshZrM77nq81YY
# uVxzmq/FdxeDWds3GhhyVKVB0rYjdaNDmuV3fJZ5t0GNv+zcgKCf0Xd1WF81E+Al
# GmcLfc4l+gcK5GEh2NQc5QfGNpn0ltDGFf5Ozdeui53bFv0ExpK91IjmqaOqu/dk
# ODtfzAzQNb50GQOmxapMomE2gj4d8yu8l13bS3g7LfU772Aj6PXsCyM2la+YZr9T
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggauMIIElqADAgECAhMzAAIbzbo3
# zXOjJ2trAAAAAhvNMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBBT0MgQ0EgMDQwHhcNMjYwNjE0MTgyMzQ4WhcNMjYwNjE3
# MTgyMzQ4WjBwMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmEx
# FDASBgNVBAcTC01vdW50IEhvbGx5MRgwFgYDVQQKEw9KYXNvbiBTbGF1Z2h0ZXIx
# GDAWBgNVBAMTD0phc29uIFNsYXVnaHRlcjCCAaIwDQYJKoZIhvcNAQEBBQADggGP
# ADCCAYoCggGBAJrGVjcF3j6/bmw5+kDB2IT3C/fJq5wu0HSuFWk0hty69lQXoX8F
# TN+j4twxsjCEWcPyuJXbSVPuWqGyzne6biDauhPjEcQVoARVE6f6q3I2DowS+UqO
# ji7M41HKPRZWZkxgAa+Skv0+fh01HrGq0rYeGMU0lR2QGAdXuUB7VMZgB3JUayVh
# ObAESBh8cQGxkaauYNs+A565/0QctDm0SIvV3UL7If7LoLscohhFK5+THxRCqAVq
# V5hl/e/tW9YZlR1v5/S53SufG7nwF62fu7bAaT2WomKiyPvD016rVcw4aToY+dvm
# 27t97EvUsRoKlWaGTlqN5Ys2lAzyx0htqbdTIq5ohHm6934LVNvXPGxgStdJ2K4u
# 8+MQe/OscOJwftL/z0HXWXL5o7KgArl5S3eF8u6i8C6WQlFKJAIm8JoA06ozYqjY
# nyzicZX73pSvNA4umRokwsgsppxsHbMtQjt3bVEqXsRTnn6BJfH5v+1RPABE6NW1
# iUWzZR5xVTyNhwIDAQABo4IB1TCCAdEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E
# BAMCB4AwPAYDVR0lBDUwMwYKKwYBBAGCN2EBAAYIKwYBBQUHAwMGGysGAQQBgjdh
# gt2s5lWC0P7oIoH92NY046SlYzAdBgNVHQ4EFgQUOLrheHvD3QIraHwUHJ9epXbv
# JgMwHwYDVR0jBBgwFoAUayVB3vtrfP0YgAotf492XapzPbgwZwYDVR0fBGAwXjBc
# oFqgWIZWaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9z
# b2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwQU9DJTIwQ0ElMjAwNC5jcmwwdAYI
# KwYBBQUHAQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEFPQyUyMENBJTIwMDQuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUF
# BwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3Np
# dG9yeS5odG0wDQYJKoZIhvcNAQEMBQADggIBAHmMtvpzmji4PSQMF0Mk6SYCYlMy
# 5oLS9Jui62/3wqGVgoQ60sDC2abowpVv2dmtVlTPThtcdHtXiBdKrGGxmjfcuDuf
# TQW+mbcHMR0I9Rw5ewQhzqMH0RiUcWf1bWQAo8UWNH8SDVRH7zhnxl7dSQzaPEtC
# CW1JaZ9SHgqGZNjaYZg0pr7j3VE9OBrVn/8D2eHbgEUqkTJF7q0GUjfaZkuFKy7U
# KH89F/xOjfNX8furGdLqGZltBVynTQFoSxJCVVxO1wR3tidwkGmc/cnpY8WyGT1V
# YPo5G6/6DjbXYcuuaDKDz8p2aLTgc/sWxSlu8Q19b7sJBQetJirB6GWKvj3DP+ut
# m2HLdlzB/krIq0RZOpW60xS88MU50SQIS1rAglPmcpUIvyULEcwp/0Vxr4mOO/Dh
# E5RjTHpR5JbUjfToVCSS91M5Ukd4Js2IY3bU/C0dDvCbSwZ3a4ELvbNBG4lnX0jT
# jqKlQKyWuYSvuIizLeII67oYLzwb6VV45hWQ8aOmJYEE9FV+RuhbxClsKlsbUS0m
# kJGC0UxHLS1tqQTkqQsC0o8QeUy4eZpjh1CIIlZ2GXVZUroEkbXCGutXyiUcZju7
# ht5ENOwDenpoprfH+4UeNWxWYyZoh8GhV2YeNB3D93RiB4Cf/YxyBHSAUVEl4ZIA
# OnR0l0ZkwExK85lAMIIGrjCCBJagAwIBAgITMwACG826N81zoydrawAAAAIbzTAN
# BgkqhkiG9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1Mg
# QU9DIENBIDA0MB4XDTI2MDYxNDE4MjM0OFoXDTI2MDYxNzE4MjM0OFowcDELMAkG
# A1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQHEwtNb3Vu
# dCBIb2xseTEYMBYGA1UEChMPSmFzb24gU2xhdWdodGVyMRgwFgYDVQQDEw9KYXNv
# biBTbGF1Z2h0ZXIwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCaxlY3
# Bd4+v25sOfpAwdiE9wv3yaucLtB0rhVpNIbcuvZUF6F/BUzfo+LcMbIwhFnD8riV
# 20lT7lqhss53um4g2roT4xHEFaAEVROn+qtyNg6MEvlKjo4uzONRyj0WVmZMYAGv
# kpL9Pn4dNR6xqtK2HhjFNJUdkBgHV7lAe1TGYAdyVGslYTmwBEgYfHEBsZGmrmDb
# PgOeuf9EHLQ5tEiL1d1C+yH+y6C7HKIYRSufkx8UQqgFaleYZf3v7VvWGZUdb+f0
# ud0rnxu58Betn7u2wGk9lqJiosj7w9Neq1XMOGk6GPnb5tu7fexL1LEaCpVmhk5a
# jeWLNpQM8sdIbam3UyKuaIR5uvd+C1Tb1zxsYErXSdiuLvPjEHvzrHDicH7S/89B
# 11ly+aOyoAK5eUt3hfLuovAulkJRSiQCJvCaANOqM2Ko2J8s4nGV+96UrzQOLpka
# JMLILKacbB2zLUI7d21RKl7EU55+gSXx+b/tUTwAROjVtYlFs2UecVU8jYcCAwEA
# AaOCAdUwggHRMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMDwGA1UdJQQ1
# MDMGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhsrBgEEAYI3YYLdrOZVgtD+6CKB/djW
# NOOkpWMwHQYDVR0OBBYEFDi64Xh7w90CK2h8FByfXqV27yYDMB8GA1UdIwQYMBaA
# FGslQd77a3z9GIAKLX+Pdl2qcz24MGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVy
# aWZpZWQlMjBDUyUyMEFPQyUyMENBJTIwMDQuY3JsMHQGCCsGAQUFBwEBBGgwZjBk
# BggrBgEFBQcwAoZYaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBBT0MlMjBDQSUyMDA0
# LmNydDBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqG
# SIb3DQEBDAUAA4ICAQB5jLb6c5o4uD0kDBdDJOkmAmJTMuaC0vSboutv98KhlYKE
# OtLAwtmm6MKVb9nZrVZUz04bXHR7V4gXSqxhsZo33Lg7n00Fvpm3BzEdCPUcOXsE
# Ic6jB9EYlHFn9W1kAKPFFjR/Eg1UR+84Z8Ze3UkM2jxLQgltSWmfUh4KhmTY2mGY
# NKa+491RPTga1Z//A9nh24BFKpEyRe6tBlI32mZLhSsu1Ch/PRf8To3zV/H7qxnS
# 6hmZbQVcp00BaEsSQlVcTtcEd7YncJBpnP3J6WPFshk9VWD6ORuv+g4212HLrmgy
# g8/Kdmi04HP7FsUpbvENfW+7CQUHrSYqwehlir49wz/rrZthy3Zcwf5KyKtEWTqV
# utMUvPDFOdEkCEtawIJT5nKVCL8lCxHMKf9Fca+Jjjvw4ROUY0x6UeSW1I306FQk
# kvdTOVJHeCbNiGN21PwtHQ7wm0sGd2uBC72zQRuJZ19I046ipUCslrmEr7iIsy3i
# COu6GC88G+lVeOYVkPGjpiWBBPRVfkboW8QpbCpbG1EtJpCRgtFMRy0tbakE5KkL
# AtKPEHlMuHmaY4dQiCJWdhl1WVK6BJG1whrrV8olHGY7u4beRDTsA3p6aKa3x/uF
# HjVsVmMmaIfBoVdmHjQdw/d0YgeAn/2McgR0gFFRJeGSADp0dJdGZMBMSvOZQDCC
# BygwggUQoAMCAQICEzMAAAAWMZKNkgJle5oAAAAAABYwDQYJKoZIhvcNAQEMBQAw
# YzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE0
# MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQQ0Eg
# MjAyMTAeFw0yNjAzMjYxODExMjlaFw0zMTAzMjYxODExMjlaMFoxCzAJBgNVBAYT
# AlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1p
# Y3Jvc29mdCBJRCBWZXJpZmllZCBDUyBBT0MgQ0EgMDQwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDKVfrI2+gJMM/0bQ5OVKNdvOASzLbUUMvXuf+Vl7YG
# uofPaZHVo3gMHF5inT+GMSpIcfIZ9qtXU1UG68ry8vNbQtOL4Nm30ifXpqI1+Byi
# AWLO1YT0WnzG7XPOuoTeeWsNZv5FmjxCsReBZvyzyzCyXZbu1EQfJxWTH4ebUwtA
# iW9rqMf9eDj/wYhiEfNteJV3ZFeibD2ztCHr9JhFdd97XbnCHgQoTIqc02X5xlRK
# tUGBa++OtHBBjiJ/uwBnzTkqu4FjpZjQeJtrmda+ur1CT2jflWIB/ypn7u7V9tvW
# 9wJbJYt/H2EtJ0GONWxJZ7TEu8jWPindOO3lzPP7UtzS/mVDV94HucWaltmsra6z
# SG8BoEJ87IM8QSb7vfm/O41FhYkUv89WIj5ES2O4kxyiMSfe95CMivCuYrRP2hKv
# x7egPMrWgDDBkxMLgrKZO9hRNUMm8vk3w5b9SogHOyJVhxyFm8aFXfIxgqDF4S0g
# 4bhbhnzljmSlCLlumMZcXFGDjpF2tNoAu3VGFGYtHtTSNVKvZpgB3b4ynaoDkbPf
# +Wg4523jt4VneasBgZhC1srZI2NCnCBBfgjLq04pqEKAWEohyW2K29KSkkHvt5Va
# E1ac3Yt+oyiOzMS57tXwQDJLGvLg/OXFO0VNvczDndfIfXYExB/ab2PuMSwd5VIB
# OwIDAQABo4IB3DCCAdgwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEA
# MB0GA1UdDgQWBBRrJUHe+2t8/RiACi1/j3ZdqnM9uDBUBgNVHSAETTBLMEkGBFUd
# IAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBB
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAU2UEpsA8PY2zvadf1zSme
# pEhqMOYwcAYDVR0fBGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENvZGUlMjBT
# aWduaW5nJTIwUENBJTIwMjAyMS5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUF
# BzAChmFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jv
# c29mdCUyMElEJTIwVmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIw
# MjEuY3J0MA0GCSqGSIb3DQEBDAUAA4ICAQAG1VBeVHTVRBljlcZD3IiMxwPyMjQy
# LNaEnVu5mODm2hRBJfH8GsBLATmrHAc8F47jmk5CnpUPiIguCbw6Z/KVj4Dsoiq2
# 28NSLMLewFfGMri7uwNGLISC5ccp8vUdADDEIsS2dE+QI9OwkDpv3XuUD7d+hAgc
# LVcMOl1AsfEZtsZenhGvSYUrm/FuLq0BqEGL9GXM5c+Ho9q8o+Vn/S+GWQN2y+gk
# RO15s0kI05nUpq/dOD4ri9rgVs6tipEd0YZqGgD+CZNiaZWrDTOQbNPncd2F9qOs
# Ua20miYruoT5PwJAaI+QQiTE2ZJeMJOkOpzhTUgqVMZwZidEUZKCqudaeQA08Wwn
# kQMfKyHzaU8j48ULcU4hUwvMsv7fSurOe9GAdRQCPvF8WcSK5oDHe8VVJM4tv6KK
# Cm91HqLx9JamBgRI6R2SfY3nu26EGznu0rCg/769z8xWm4PVcC2ZaL6VlKVqFp1N
# sN8YqMyf5t+bbGVb09noFKcJG/UwyGlxRmQBlfeBUQx5/ytlzZzsEnhrJF9fTAfj
# e8j3OdX5lEnePTFQLRlvzZFBqUXnIeQKv3fHQjC9m2fo/Z01DII/qp3d8LhGVUW0
# BCG04fRwHJNH8iqqCG/qofMv+kym2AxBDnHzNgRjL60JOFiBgiurvLhYQNhB95KW
# ojFA6shQnggkMTCCB54wggWGoAMCAQICEzMAAAAHh6M0o3uljhwAAAAAAAcwDQYJ
# KoZIhvcNAQEMBQAwdzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjFIMEYGA1UEAxM/TWljcm9zb2Z0IElkZW50aXR5IFZlcmlmaWNh
# dGlvbiBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDIwMB4XDTIxMDQwMTIw
# MDUyMFoXDTM2MDQwMTIwMTUyMFowYzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlm
# aWVkIENvZGUgU2lnbmluZyBQQ0EgMjAyMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBALLwwK8ZiCji3VR6TElsaQhVCbRS/3pK+MHrJSj3Zxd3KU3rlfL3
# qrZilYKJNqztA9OQacr1AwoNcHbKBLbsQAhBnIB34zxf52bDpIO3NJlfIaTE/xrw
# eLoQ71lzCHkD7A4As1Bs076Iu+mA6cQzsYYH/Cbl1icwQ6C65rU4V9NQhNUwgrx9
# rGQ//h890Q8JdjLLw0nV+ayQ2Fbkd242o9kH82RZsH3HEyqjAB5a8+Ae2nPIPc8s
# ZU6ZE7iRrRZywRmrKDp5+TcmJX9MRff241UaOBs4NmHOyke8oU1TYrkxh+YeHgfW
# o5tTgkoSMoayqoDpHOLJs+qG8Tvh8SnifW2Jj3+ii11TS8/FGngEaNAWrbyfNrC6
# 9oKpRQXY9bGH6jn9NEJv9weFxhTwyvx9OJLXmRGbAUXN1U9nf4lXezky6Uh/cgjk
# Vd6CGUAf0K+Jw+GE/5VpIVbcNr9rNE50Sbmy/4RTCEGvOq3GhjITbCa4crCzTTHg
# YYjHs1NbOc6brH+eKpWLtr+bGecy9CrwQyx7S/BfYJ+ozst7+yZtG2wR461uckFu
# 0t+gCwLdN0A6cFtSRtR8bvxVFyWwTtgMMFRuBa3vmUOTnfKLsLefRaQcVTgRnzeL
# zdpt32cdYKp+dhr2ogc+qM6K4CBI5/j4VFyC4QFeUP2YAidLtvpXRRo3AgMBAAGj
# ggI1MIICMTAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0O
# BBYEFNlBKbAPD2Ns72nX9c0pnqRIajDmMFQGA1UdIARNMEswSQYEVR0gADBBMD8G
# CCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3Mv
# UmVwb3NpdG9yeS5odG0wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTIftJqhSobyhmYBAcnz1AQT2ioojCBhAYD
# VR0fBH0wezB5oHegdYZzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIw
# Q2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIwLmNybDCBwwYIKwYBBQUHAQEE
# gbYwgbMwgYEGCCsGAQUFBzAChnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIw
# Um9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQwLQYIKwYB
# BQUHMAGGIWh0dHA6Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20vb2NzcDANBgkqhkiG
# 9w0BAQwFAAOCAgEAfyUqnv7Uq+rdZgrbVyNMul5skONbhls5fccPlmIbzi+OwVdP
# Q4H55v7VOInnmezQEeW4LqK0wja+fBznANbXLB0KrdMCbHQpbLvG6UA/Xv2pfpVI
# E1CRFfNF4XKO8XYEa3oW8oVH+KZHgIQRIwAbyFKQ9iyj4aOWeAzwk+f9E5StNp5T
# 8FG7/VEURIVWArbAzPt9ThVN3w1fAZkF7+YU9kbq1bCR2YD+MtunSQ1Rft6XG7b4
# e0ejRA7mB2IoX5hNh3UEauY0byxNRG+fT2MCEhQl9g2i2fs6VOG19CNep7SquKaB
# jhWmirYyANb0RJSLWjinMLXNOAga10n8i9jqeprzSMU5ODmrMCJE12xS/NWShg/t
# uLjAsKP6SzYZ+1Ry358ZTFcx0FS/mx2vSoU8s8HRvy+rnXqyUJ9HBqS0DErVLjQw
# K8VtsBdekBmdTbQVoCgPCqr+PDPB3xajYnzevs7eidBsM71PINK2BoE2UfMwxCCX
# 3mccFgx6UsQeRSdVVVNSyALQe6PT12418xon2iDGE81OGCreLzDcMAZnrUAx4XQL
# Uz6ZTl65yPUiOh3k7Yww94lDf+8oG2oZmDh5O1Qe38E+M3vhKwmzIeoB1dVLlz4i
# 3IpaDcR+iuGjH2TdaC1ZOmBXiCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqU
# MIIakAIBATBxMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBBT0Mg
# Q0EgMDQCEzMAAhvNujfNc6Mna2sAAAACG80wDQYJYIZIAWUDBAIBBQCgXjAQBgor
# BgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG
# 9w0BCQQxIgQgJ5Q2/zP3qsv++7V8ugm4bbk4CG89oqmsfLKbCRSGqkAwDQYJKoZI
# hvcNAQEBBQAEggGALnve4J4J73W7H+RYDXiFphamQFbyS8kz9O+ZECk8A1MOcF7r
# scMP+AVmQQS63zRjnGxOzJtxF+KWMx9e1lBebrgp+iHjP+qGtQiPi/lXsCWZlZ6f
# 3nfafV/6rfo4JxtWOfT0O36wT2TzVOS72EDVLtDkUNsZPJx4mRzUcO6D6mtwq8bx
# GICC2p2VXncyNWR3hsjtcFNOHS7ejWlyFoQpp08kmWUDBtDwN/a5R43a0ISdD4vU
# IqgCreIoG4ipSC2l/01AvIPunY3o7UDzd+PBENIMlOVmI02EgTy9EZHU9WNIcQGO
# fh7nvEZrGGlxpFhy209DzKeB5SKSD0dM0lL+ekHpwzAXB01UkvSiJQuqsvt+mZ/E
# CGeLPfJOFZJ8W1Gj6exl4zIhXZ/qiWidPoLcxoo566ZTvLScPvO5qqo/RtGLn7vM
# fLVWO57Q9c7RKYhvDj7mNTXUgEUPDJl7JmF2Ii4CFZyQZUHAK5SerXri4D/mpPcx
# feW5aa2ROrSB+79XoYIYFDCCGBAGCisGAQQBgjcDAwExghgAMIIX/AYJKoZIhvcN
# AQcCoIIX7TCCF+kCAQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEE
# oIIBUQSCAU0wggFJAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIGYY
# CSvscv342uVA56qz3CycXM6O3Eh3BmjYP7Uy7eC3AgZqHFbueswYEzIwMjYwNjE1
# MTkyNTA2Ljc1OVowBIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJh
# dGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBNTAwLTA1RTAtRDk0NzE1
# MDMGA1UEAxMsTWljcm9zb2Z0IFB1YmxpYyBSU0EgVGltZSBTdGFtcGluZyBBdXRo
# b3JpdHmggg8hMIIHgjCCBWqgAwIBAgITMwAAAAXlzw//Zi7JhwAAAAAABTANBgkq
# hkiG9w0BAQwFADB3MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMUgwRgYDVQQDEz9NaWNyb3NvZnQgSWRlbnRpdHkgVmVyaWZpY2F0
# aW9uIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMjAwHhcNMjAxMTE5MjAz
# MjMxWhcNMzUxMTE5MjA0MjMxWjBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJT
# QSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAJ5851Jj/eDFnwV9Y7UGIqMcHtfnlzPREwW9ZUZHd5HBXXBvf7KrQ5cM
# SqFSHGqg2/qJhYqOQxwuEQXG8kB41wsDJP5d0zmLYKAY8Zxv3lYkuLDsfMuIEqvG
# YOPURAH+Ybl4SJEESnt0MbPEoKdNihwM5xGv0rGofJ1qOYSTNcc55EbBT7uq3wx3
# mXhtVmtcCEr5ZKTkKKE1CxZvNPWdGWJUPC6e4uRfWHIhZcgCsJ+sozf5EeH5KrlF
# nxpjKKTavwfFP6XaGZGWUG8TZaiTogRoAlqcevbiqioUz1Yt4FRK53P6ovnUfANj
# IgM9JDdJ4e0qiDRm5sOTiEQtBLGd9Vhd1MadxoGcHrRCsS5rO9yhv2fjJHrmlQ0E
# IXmp4DhDBieKUGR+eZ4CNE3ctW4uvSDQVeSp9h1SaPV8UWEfyTxgGjOsRpeexIve
# R1MPTVf7gt8hY64XNPO6iyUGsEgt8c2PxF87E+CO7A28TpjNq5eLiiunhKbq0Xbj
# kNoU5JhtYUrlmAbpxRjb9tSreDdtACpm3rkpxp7AQndnI0Shu/fk1/rE3oWsDqMX
# 3jjv40e8KN5YsJBnczyWB4JyeeFMW3JBfdeAKhzohFe8U5w9WuvcP1E8cIxLoKSD
# zCCBOu0hWdjzKNu8Y5SwB1lt5dQhABYyzR3dxEO/T1K/BVF3rV69AgMBAAGjggIb
# MIICFzAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYE
# FGtpKDo1L0hjQM972K9J6T7ZPdshMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsG
# AQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVw
# b3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTIftJqhSob
# yhmYBAcnz1AQT2ioojCBhAYDVR0fBH0wezB5oHegdYZzaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJp
# ZmljYXRpb24lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIw
# LmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwgYEGCCsGAQUFBzAChnVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElkZW50aXR5
# JTIwVmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5
# JTIwMjAyMC5jcnQwDQYJKoZIhvcNAQEMBQADggIBAF+Idsd+bbVaFXXnTHho+k7h
# 2ESZJRWluLE0Oa/pO+4ge/XEizXvhs0Y7+KVYyb4nHlugBesnFqBGEdC2IWmtKMy
# S1OWIviwpnK3aL5JedwzbeBF7POyg6IGG/XhhJ3UqWeWTO+Czb1c2NP5zyEh89F7
# 2u9UIw+IfvM9lzDmc2O2END7MPnrcjWdQnrLn1Ntday7JSyrDvBdmgbNnCKNZPmh
# zoa8PccOiQljjTW6GePe5sGFuRHzdFt8y+bN2neF7Zu8hTO1I64XNGqst8S+w+RU
# die8fXC1jKu3m9KGIqF4aldrYBamyh3g4nJPj/LR2CBaLyD+2BuGZCVmoNR/dSpR
# Cxlot0i79dKOChmoONqbMI8m04uLaEHAv4qwKHQ1vBzbV/nG89LDKbRSSvijmwJw
# xRxLLpMQ/u4xXxFfR4f/gksSkbJp7oqLwliDm/h+w0aJ/U5ccnYhYb7vPKNMN+SZ
# DWycU5ODIRfyoGl59BsXR/HpRGtiJquOYGmvA/pk5vC1lcnbeMrcWD/26ozePQ/T
# WfNXKBOmkFpvPE8CH+EeGGWzqTCjdAsno2jzTeNSxlx3glDGJgcdz5D/AAxw9Sdg
# q/+rY7jjgs7X6fqPTXPmaCAJKVHAP19oEjJIBwD1LyHbaEgBxFCogYSOiUIr0Xqc
# r1nJfiWG2GwYe6ZoAF1bMIIHlzCCBX+gAwIBAgITMwAAAFZ+j51YCI7pYAAAAAAA
# VjANBgkqhkiG9w0BAQwFADBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBU
# aW1lc3RhbXBpbmcgQ0EgMjAyMDAeFw0yNTEwMjMyMDQ2NTFaFw0yNjEwMjIyMDQ2
# NTFaMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYD
# VQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hp
# ZWxkIFRTUyBFU046QTUwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQ
# dWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAtKWfm/ul027/d8Rlb8Mn/g0QUvvLqY2Vsy3tI8U2
# tFSspTZomZOD3BHT8LkR+RrhMJgb1VjAKFNysaK9cLSXifPGSIBrPCgs9P4y24lr
# JEmrV6Q5z4BmqMhIPrZhEvZnWpCS4HO7jYSei/nxmC7/1Er+l5Lg3PmSxb8d2IVc
# ARxSw1B4mxB6XI0nkel9wa1dYb2wfGpofraFmxZOxT9eNht4LH0RBSVueba6ZNpj
# S/0gtfm7qiIiyP6p6PRzTTbMnVqsHnV/d/rW0zHx+Q+QNZ5wUqKmTZJB9hU853+2
# pX5rDfK32uNY9/WBOAmzbqgpEdQkbiMavUMyUDShmycIvgHdQnS207sTj8M+kJL3
# tOdahPuPqMwsaCCgdfwwQx0O9TKe7FSvbAEYs1AnldCl/KHGZCOVvUNqjyL10JLe
# 0/+GD9/ynqXGWFpXOjaunvZ/cKROhjN4M5e6xx0b2miqcPii4/ii2ZheKallJET7
# CKlpFShs3wyg6F/fojQxQvPnbWD4Nyx6lhjWjwmoLcx6w1FSCtavLCly33BLRSlT
# U4qKUxaa8d7YN7Eqpn9XO0SY0umOvKFXrWH7rxl+9iaicitdnTTksAnRjvekdKT3
# lg7lRMfmfZU8vXNiN0UYJzT9EjqjRm0uN/h0oXxPhNfPYqeFbyPXGGxzaYUz6zx3
# qTcCAwEAAaOCAcswggHHMB0GA1UdDgQWBBS+tjPyu6tZ/h5GsyLvyz1H+FNIWjAf
# BgNVHSMEGDAWgBRraSg6NS9IY0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6Bd
# hltodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkG
# CCsGAQUFBwEBBG0wazBpBggrBgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1l
# c3RhbXBpbmclMjBDQSUyMDIwMjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYB
# BAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcN
# AQEMBQADggIBAA4DqAXEsO26j/La7Fgn/Qifit8xuZekqZ57+Ye+sH/hRTbEEjGY
# rZgsqwR/lUUfKCFpbZF8msaZPQJOR4YYUEU8XyjLrn8Y1jCSmoxh9l7tWiSoc/JF
# Bw356JAmzGGxeBA2EWSxRuTr1AuZe6nYaN8/wtFkiHcs8gMadxXBs6DxVhyu5Ynh
# LPQkfumKm3lFftwE7pieV7f1lskmlgsC6AeSGCzGPZUgCvcH5Tv/Qe9z7bIImSD3
# SuzhOIwaP+eKQTYf67TifyJKkWQSdGfTA6Kcu41k8LB6oPK+MLk1jbxxK5wPqLSL
# 62xjK04SBXHEJSEnsFt0zxWkxP/lgej1DxqUnmrYEdkxvzKSHIAqFWSZul/5hI+v
# JxvFPhsNQBEk4cSulDkJQpcdVi/gmf/mHFOYhDBjsa15s4L+2sBil3XV/T8RiR66
# Q8xYvTLRWxd2dVsrOoCwnsU4WIeiC0JinCv1WLHEh7Qyzr9RSr4kKJLWdpNYLhgj
# kojTmEkAjFO774t3xB7enbvIF0GOsV19xnCUzq9EGKyt0gMuaphKlNjJ+aTpjWMZ
# DGo+GOKsnp93Hmftml0Syp3F9+M3y+y6WJGUZoIZJq227jDjjEndtpUrh9BdPdVI
# fVJD/Au81Rzh05UHAivorQ3Os8PELHIgiOd9TWzbdgmGzcILt/ddVQERMYIHRjCC
# B0ICAQEweDBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBp
# bmcgQ0EgMjAyMAITMwAAAFZ+j51YCI7pYAAAAAAAVjANBglghkgBZQMEAgEFAKCC
# BJ8wEQYLKoZIhvcNAQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAcBgkqhkiG9w0BCQUxDxcNMjYwNjE1MTkyNTA2WjAvBgkqhkiG9w0BCQQxIgQg
# y/znZIf6NlZD3Nr4o/WJOmDYvzjHw+xhpgBzkevJ+TYwgbkGCyqGSIb3DQEJEAIv
# MYGpMIGmMIGjMIGgBCC2DDMlTaTj8JV3iTg5Xnpe4CSH60143Z+X9o5NBgMMqDB8
# MGWkYzBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcg
# Q0EgMjAyMAITMwAAAFZ+j51YCI7pYAAAAAAAVjCCA2EGCyqGSIb3DQEJEAISMYID
# UDCCA0yhggNIMIIDRDCCAiwCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTUwMC0wNUUw
# LUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBp
# bmcgQXV0aG9yaXR5oiMKAQEwBwYFKw4DAhoDFQD/c/cpFSqQWYBeXggyRJ2ZbvYE
# EaBnMGWkYzBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBp
# bmcgQ0EgMjAyMDANBgkqhkiG9w0BAQsFAAIFAO3am9owIhgPMjAyNjA2MTUxNTQy
# MThaGA8yMDI2MDYxNjE1NDIxOFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA7dqb
# 2gIBADAKAgEAAgIc8AIB/zAHAgEAAgISUDAKAgUA7dvtWgIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBCwUAA4IBAQBP1ZkH0VP/71hdf5Wve3ppH2E8cai/JT56byFGfj96
# weTGPHU3gOPBwsqDVtu//KvcPckZ2MylHFQb7qT1bZiLzvIEvcKne17JB/M7gWkH
# GDVZfy9CGcMIpYPTT4jUxBfPI7FAy0o5nTE7ZDpz4KgX7nw6r7EyvlZlNFwz3J93
# s8JneJF9+7ZR3xWT6KZwww1sPEK+xIPvk7mfIiBWhW+XVfQsC2cS79Mv1hD3gAMJ
# J+Akk3jZD2imum9OMX3aTQ+/N9VqQ9Odn6CNfKtl3pMGgh8KkJ0/c+HiC5qVCKak
# 9IpVnHig9XtXBjNr6mXep8Li8Mn6x8BkH+ZHAxCF9fk9MA0GCSqGSIb3DQEBAQUA
# BIICADXtaf11FlU2l80WleeB8uNilq2OUuxqm5bbBZieqC+qhvbn5rzs2Sxwof9i
# KMMHgUXU0htNpSJh0B0cb0gsMbh8/ZuvgGAinAAuuQcrzf418XPl1daZkuRKeQMY
# MlhFmw9qaKGFO51zor9K41E09rZSPe3NsEizFItx0JLlYZPqkKQ9ptUTsg5GawgZ
# tzUO48CESkg0zXB3fzY8fQRKuHWKRKmVDfMx2G5Fm+3aAJfTBHJKGDm65KdFSdZU
# scRRCbegEFYa6aBsBa2WD3FX8L4fEhHlqkLj1x88U25+nYvAFYa1e5DFr0FrwXU7
# bvmzmFyAyZ1PpFBNFRrnXO73aHXdX9ZtpgEZKZL08aNO6QBfWLTgrR4M8kdt51wM
# dgLgH+VPOPKh+0xORi1qtKhs6V3lYTn37wrDGl4OhmiFfwYO4z7BMa6pI9SsUfQn
# HJl0Zf9P0ayRZlzL+W0oYAtUW4tTI61+BJ9ahhc3qBfh8ZTUJqkWPVuSp7J+xKRh
# 0ovCflS3jysodQ7BoKuNP/WZNnbkYNOB8c8AxNlcbA8b5dAWeNPy23d8MITCe+QA
# D6oI2CYSLFthzrDe1SrZtQt2c//4AQEgsET97YATz5GO0frEqmjI+zHq+W6mZEbS
# Alpd7tbqCO3r56fnaw7uWAeXPfnK8+7AoEChixCZgEPID3Eg
# SIG # End signature block
