##################################################################################
# MIT License                                                                    #
#                                                                                #
# Copyright (c) 2022 Jason                                                       #
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
    
    ## https://learn.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols
    ## Note regarding "Default" setting -- Despite the name of this field, SslStream does not use it as a default except
    ## under special circumstances, and is considered obsolete. Use "None" to allow the OS to choose.
    [ValidateSet('None', 'Ssl2', 'Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13', 'Default')]
    [string[]]$ForceProtocolVersion = @('None')
)

Process
{
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

        # At-a-glance info
        Write-Host "Subject: $($x509.Subject)"
        Write-Host "Validity period: $($x509.NotBefore) to $($x509.NotAfter)"

        $sanExtension = $x509.Extensions["2.5.29.17"]
        if ($sanExtension -ne $null) 
        {
            $sanData = New-Object System.Security.Cryptography.AsnEncodedData -ArgumentList $sanExtension.Oid, $sanExtension.RawData
            $sanStrings = $sanData.Format($true)

            Write-Host "Subject alternative names (SAN):"
            Write-Host $sanStrings
        }

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

        if ($ForceProtocolVersion)
        {
            # Default value if none given
            $ForcedProtocols = [System.Security.Authentication.SslProtocols]::None

            foreach ($version in $ForceProtocolVersion) {
                $ForcedProtocols = $ForcedProtocols -bor [System.Security.Authentication.SslProtocols]::$version
            }
        }
        
        if ($ForcedProtocols -ne [System.Security.Authentication.SslProtocols]::None)
        {
            Write-Host "Forcing protocol version(s): $ForcedProtocols"
        }
        
        $ssl = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false, $dumpCertInfo
        $ssl.AuthenticateAsClient($Endpoint, $null, $ForcedProtocols, $true)
    }
    catch
    {
        Write-Host $error
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
# MII9PQYJKoZIhvcNAQcCoII9LjCCPSoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBXzf4S8+BvZiwk
# G5KJ5ByM1rCj3GNNvDQ5D/OhQeCin6CCIgIwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggauMIIElqADAgECAhMzAAHqObaw
# 9melNIAuAAAAAeo5MA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwHhcNMjYwNjEzMTgyMTA5WhcNMjYwNjE2
# MTgyMTA5WjBwMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmEx
# FDASBgNVBAcTC01vdW50IEhvbGx5MRgwFgYDVQQKEw9KYXNvbiBTbGF1Z2h0ZXIx
# GDAWBgNVBAMTD0phc29uIFNsYXVnaHRlcjCCAaIwDQYJKoZIhvcNAQEBBQADggGP
# ADCCAYoCggGBAIXWXn1FMLyrTCdaR8t31+n0P+tenvpHAVankWjiizL9eHC9u0vF
# QOPmPbGf8uYQdb5G7Ij1uxiBi/daCMqpJtNdBN/N3WOlhAwT4K0hReGmH995+OIR
# B0dxGDJdsdpbhaKKr0I5Sd+37DV15WAG63Eqm2wnTctDqOOnD5ZkuU0jWKOZN5J/
# mB3zbQ+tDfYK/nNJhHI7P+2s+s/lLH4RNswr5RrJnXa8qESY2Qb3osKmLp8h+tz2
# GF9tfDwLVFPIKnw1FcPzNTdGTN00Gns0wUV5EDrkcJBxA1yaTNbCXdXfL0v6v3Tr
# griVHLrj4HcxeeBILx7Dtjs4LS1eSr7IGKLqmWyBU+1jrVjbZIRp8srHbsVK2Xut
# q2ajPgOhDOPdGE4TXvLg82jeQrwVYPTUVKpJow7dM5wfCV3B1Cvyx/BCjkMT+qH7
# fYg6+gMfcgTctkiUe6ENwGhBiHLoSvyCL7eBRp05OzYGYcsYt/SiBYXNU5pXvjIz
# P1yKETR8u1SabQIDAQABo4IB1TCCAdEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E
# BAMCB4AwPAYDVR0lBDUwMwYKKwYBBAGCN2EBAAYIKwYBBQUHAwMGGysGAQQBgjdh
# gt2s5lWC0P7oIoH92NY046SlYzAdBgNVHQ4EFgQUk9K+tM1S+mcNheirZt451TGq
# EsAwHwYDVR0jBBgwFoAUa16lNMMFxWJKIVqOq3NgYtSsY4UwZwYDVR0fBGAwXjBc
# oFqgWIZWaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9z
# b2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMy5jcmwwdAYI
# KwYBBQUHAQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEVPQyUyMENBJTIwMDMuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUF
# BwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3Np
# dG9yeS5odG0wDQYJKoZIhvcNAQEMBQADggIBAH4zxr1dESfLhOKj1zGXXCbGgDAF
# 0t5iIE6NbXLxXePh4obmeKxPwO7OY8G06f4JJL98vlpihARkJd7p3O1T/q+Ej6w4
# l3Cf2+BxDPdex8LSCyOPmpXZ51Z/d3Kb9h8SKeJ934VyTAl7kln8nkol0xj19GyW
# 4McGuNMFug436xDJWb7C6Tk1/2L5tRauwNnXxwix+YfUabPgjmZrWcoDo9aIXkBm
# DQbbsfApW2h5q+aSTIe4jvrQ3P/Nc/JCWqWQlCdbeCqc1+OEpHTOfmO00u72qAsp
# PR3hgMJgHk3C0PG2dzcahviULcjFLV4duy5d3bA5lpisHmpHH5cm03TxNj2auOUs
# +tChWpGJwqCfpr1HARNQt15/zNvRsCFGYpsJwzRYZV+a/0nzvT0HowjgQ7lCzRBb
# 6RHyDmI9wq98WugGghkVkDr3WgVdRwHNsV+OptJiWaiStdYgvDrXID5RovrjU3bN
# 7pb6t6ZmJdubw29G9bz4X9ykn4Uwukoc3hvRo+iFZSQM3F+m5CIXY9og66WmvWLV
# w3Z+XXvx7a0Og7MfH4ad+zGCYOMgYcf7FkhwAAVJ0RGSV31PMwcANZrsypTvvuJq
# LjXNZ5+ZqytWSAYq8rD/SWDY5m+m8VmbBpCxeio+8hjoTvB17fs8ahPm5TEMJXhH
# sBQCiiuqXgl3tHEUMIIGrjCCBJagAwIBAgITMwAB6jm2sPZnpTSALgAAAAHqOTAN
# BgkqhkiG9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1Mg
# RU9DIENBIDAzMB4XDTI2MDYxMzE4MjEwOVoXDTI2MDYxNjE4MjEwOVowcDELMAkG
# A1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQHEwtNb3Vu
# dCBIb2xseTEYMBYGA1UEChMPSmFzb24gU2xhdWdodGVyMRgwFgYDVQQDEw9KYXNv
# biBTbGF1Z2h0ZXIwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCF1l59
# RTC8q0wnWkfLd9fp9D/rXp76RwFWp5Fo4osy/XhwvbtLxUDj5j2xn/LmEHW+RuyI
# 9bsYgYv3WgjKqSbTXQTfzd1jpYQME+CtIUXhph/fefjiEQdHcRgyXbHaW4Wiiq9C
# OUnft+w1deVgButxKptsJ03LQ6jjpw+WZLlNI1ijmTeSf5gd820PrQ32Cv5zSYRy
# Oz/trPrP5Sx+ETbMK+UayZ12vKhEmNkG96LCpi6fIfrc9hhfbXw8C1RTyCp8NRXD
# 8zU3RkzdNBp7NMFFeRA65HCQcQNcmkzWwl3V3y9L+r9064K4lRy64+B3MXngSC8e
# w7Y7OC0tXkq+yBii6plsgVPtY61Y22SEafLKx27FStl7ratmoz4DoQzj3RhOE17y
# 4PNo3kK8FWD01FSqSaMO3TOcHwldwdQr8sfwQo5DE/qh+32IOvoDH3IE3LZIlHuh
# DcBoQYhy6Er8gi+3gUadOTs2BmHLGLf0ogWFzVOaV74yMz9cihE0fLtUmm0CAwEA
# AaOCAdUwggHRMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMDwGA1UdJQQ1
# MDMGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhsrBgEEAYI3YYLdrOZVgtD+6CKB/djW
# NOOkpWMwHQYDVR0OBBYEFJPSvrTNUvpnDYXoq2beOdUxqhLAMB8GA1UdIwQYMBaA
# FGtepTTDBcViSiFajqtzYGLUrGOFMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVy
# aWZpZWQlMjBDUyUyMEVPQyUyMENBJTIwMDMuY3JsMHQGCCsGAQUFBwEBBGgwZjBk
# BggrBgEFBQcwAoZYaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAz
# LmNydDBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqG
# SIb3DQEBDAUAA4ICAQB+M8a9XREny4Tio9cxl1wmxoAwBdLeYiBOjW1y8V3j4eKG
# 5nisT8DuzmPBtOn+CSS/fL5aYoQEZCXe6dztU/6vhI+sOJdwn9vgcQz3XsfC0gsj
# j5qV2edWf3dym/YfEinifd+FckwJe5JZ/J5KJdMY9fRsluDHBrjTBboON+sQyVm+
# wuk5Nf9i+bUWrsDZ18cIsfmH1Gmz4I5ma1nKA6PWiF5AZg0G27HwKVtoeavmkkyH
# uI760Nz/zXPyQlqlkJQnW3gqnNfjhKR0zn5jtNLu9qgLKT0d4YDCYB5NwtDxtnc3
# Gob4lC3IxS1eHbsuXd2wOZaYrB5qRx+XJtN08TY9mrjlLPrQoVqRicKgn6a9RwET
# ULdef8zb0bAhRmKbCcM0WGVfmv9J8709B6MI4EO5Qs0QW+kR8g5iPcKvfFroBoIZ
# FZA691oFXUcBzbFfjqbSYlmokrXWILw61yA+UaL641N2ze6W+remZiXbm8NvRvW8
# +F/cpJ+FMLpKHN4b0aPohWUkDNxfpuQiF2PaIOulpr1i1cN2fl178e2tDoOzHx+G
# nfsxgmDjIGHH+xZIcAAFSdERkld9TzMHADWa7MqU777iai41zWefmasrVkgGKvKw
# /0lg2OZvpvFZmwaQsXoqPvIY6E7wde37PGoT5uUxDCV4R7AUAoorql4Jd7RxFDCC
# BygwggUQoAMCAQICEzMAAAAVBT5uGY6TKdkAAAAAABUwDQYJKoZIhvcNAQEMBQAw
# YzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE0
# MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQQ0Eg
# MjAyMTAeFw0yNjAzMjYxODExMjhaFw0zMTAzMjYxODExMjhaMFoxCzAJBgNVBAYT
# AlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1p
# Y3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDg9Ms9AqovDnMePvMOe+KybhCd8+lokzYORlS3kBVX
# seecbyGwBcsenlm5bLtMGPjiIFLzBQF+ghlVV/U29q5GcdeEEBCHTTGhL2koIrLc
# 4UrliMRcbv9mOMtR/l7/xAmv0Fx4BJHn1dHt37fvrBqXmKjKfGf5DpyO/+hnV7TE
# reMtS19iO+bjZ/9Hnpg3PCk0e7YSbRTFkx97FZwRWpC4s3NepRfRXQh/WMAj7Jms
# YeVZohi4TF5yW2JMrJZqwHcyzJZYtD2Hlno5ZEJkdiZcEaxHOobmwO06Z1J9c23p
# s9PGIhGaq1sKLEAz9Doc5rLkYWGteDrscKhAp2kIc/oYlH9Ij6BkOqqgWINEkEtC
# 8ZNG1Mak+h3o65aj0iQKmdxW7IZaHO5cuyoMi+KtYfXeIIg3sVIbS2EL8kUtsDGd
# EqNqAq/isqTi1jXqLe6iKp1ni1SPdvPW9G03CTsYF68b/yuIQRwbdoBCXemMNJCS
# 0dorCRY4b2WAAy4ng7SANcEgrBgZf535+QfLU5hGzrKjIpbMabauWb5FKWUKkMsP
# cXFkXRWO4noKPm4KWlFypqOpbJ/KONVReIlxHQRegAOBzIhRB7gr9IDQ1sc2MgOg
# Q+xVGW4oq4HD0mfAiwiyLskZrkaQ7JoanYjBNcR9RS26YxAVbcBtLitFTzCIEg5Z
# dQIDAQABo4IB3DCCAdgwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEA
# MB0GA1UdDgQWBBRrXqU0wwXFYkohWo6rc2Bi1KxjhTBUBgNVHSAETTBLMEkGBFUd
# IAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBB
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAU2UEpsA8PY2zvadf1zSme
# pEhqMOYwcAYDVR0fBGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENvZGUlMjBT
# aWduaW5nJTIwUENBJTIwMjAyMS5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUF
# BzAChmFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jv
# c29mdCUyMElEJTIwVmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIw
# MjEuY3J0MA0GCSqGSIb3DQEBDAUAA4ICAQBdbiI8zwXLX8glJEh/8Q22UMCUhWBO
# 46Z9FPhwOR3mdlqRVLkYOon/MczUwrjDhx3X99SPH5PSflkGoTvnO9ZWHM5YFVYp
# O7NYuB+mfVSGAGZwiGOASWk0i2B7vn9nElJJmoiXxugfH5YdBsrUgTt0AFNXkzmq
# Tgk+S1Hxb1u/0HCqEHVZPk2A/6eJXYbtpRM5Fcz00jisUl9BRZgSebODV85bBzOv
# eqyC3f0PnHCxRJNhMb8xP/sB/VI7pf2rheSV7zqUSv8vn/fIMblXeaVIlpqoq8SP
# 9BJMjE/CoVXJxnkZQRM1Fa7kN9yztvReOhxSgPgpZx/Xl/jkwyEFVJTBfBp3sTgf
# Ic/pmqv2ehtakL2AEj78EmOPQohxJT3wyX+P78GA25tLpAvzj3RMMHd8z18ZuuVi
# +60MAzGpOASH1L8Nlr3fZRZnQO+pyye2DCvYmHaIfdUgYJqn7noxxGVv89+RaETh
# 1tgCDvwNpFCSG7vl5A4ako+2fx409r9TWjXC7Oif1IQ5ZJzB4Rf8GvBiHYjvMmHp
# ledp1FGRLdSRFVpC3/OKpZY6avIqZp7+8pP/WQP903DdgrvAT6W4xPOBxXPa4tGk
# sN3SuqJaiFYHSNyeBufn8iseujW4IbBSbHD4BPqbF3qZ+7nG9d/d/G2/Lx4kH9cC
# mBfmsZdSkHmukDCCB54wggWGoAMCAQICEzMAAAAHh6M0o3uljhwAAAAAAAcwDQYJ
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
# 3IpaDcR+iuGjH2TdaC1ZOmBXiCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqR
# MIIajQIBATBxMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0Mg
# Q0EgMDMCEzMAAeo5trD2Z6U0gC4AAAAB6jkwDQYJYIZIAWUDBAIBBQCgXjAQBgor
# BgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG
# 9w0BCQQxIgQgjhvsJIAZhjJMrUNv3HXXuS2ObXvW6INyrpm3jJk17jowDQYJKoZI
# hvcNAQEBBQAEggGANDr7JSjf4Vbdj9k+PtRKouVaSNdsqi4GKQpW+T+FWgh2LhTv
# uYCIXEi7QcqT4j3QPrw8LEwxWPpgGb0w02oYvBotJ6Mf8WmKesNTotx11mZBGry3
# QYDVkjRbmDi1UMBQUfiyy4amfN8XrHSJZZryFbgs0zu/wGL3MrAahYmkwW0hKv1u
# WIsEUel5KSDvC6YMnXDUkQ8Hee4ztR96+zKIZIzIh3oGnqahFepuqimigT4V16pC
# 71cLj5AwRvKX8I0+2F6H50fBz7lRxvMBPTs0qEQULnn8CW+5fcgIu7TeCqH6vJb3
# 6N0eWaRifdIijYdamMxOXV7R708rjSsSYcE26Feibxwfv6JG8Aa5TPN8W0DhaLd/
# TC3vNsEFX678k3COdKKnfYOzoLIwUQN7g6renaR/NS/ZeOSEYiTw1COCo2q9eY1A
# qRFFK+iVflVl/CMuDqj/gc4LWhjUMTt/pw1E+d5MFNA0uVYHjMRbpApSKFo7C/mX
# lkUzot7Mj6gHGt0joYIYETCCGA0GCisGAQQBgjcDAwExghf9MIIX+QYJKoZIhvcN
# AQcCoIIX6jCCF+YCAQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEE
# oIIBUQSCAU0wggFJAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIArC
# lVzbHTIl4gTujHmblDFS5BYEM7hBmlGsRQvu8t7pAgZqHFbt3/EYEzIwMjYwNjE1
# MTQyNTU4LjUzNlowBIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
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
# fVJD/Au81Rzh05UHAivorQ3Os8PELHIgiOd9TWzbdgmGzcILt/ddVQERMYIHQzCC
# Bz8CAQEweDBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBp
# bmcgQ0EgMjAyMAITMwAAAFZ+j51YCI7pYAAAAAAAVjANBglghkgBZQMEAgEFAKCC
# BJwwEQYLKoZIhvcNAQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAcBgkqhkiG9w0BCQUxDxcNMjYwNjE1MTQyNTU4WjAvBgkqhkiG9w0BCQQxIgQg
# 8/B7XqJ5SZsbMQjCjOEdulMpCtdSVta8/EL4nxi8V0cwgbkGCyqGSIb3DQEJEAIv
# MYGpMIGmMIGjMIGgBCC2DDMlTaTj8JV3iTg5Xnpe4CSH60143Z+X9o5NBgMMqDB8
# MGWkYzBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcg
# Q0EgMjAyMAITMwAAAFZ+j51YCI7pYAAAAAAAVjCCA14GCyqGSIb3DQEJEAISMYID
# TTCCA0mhggNFMIIDQTCCAikCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTUwMC0wNUUw
# LUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBp
# bmcgQXV0aG9yaXR5oiMKAQEwBwYFKw4DAhoDFQD/c/cpFSqQWYBeXggyRJ2ZbvYE
# EaBnMGWkYzBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBp
# bmcgQ0EgMjAyMDANBgkqhkiG9w0BAQsFAAIFAO3Z8xowIhgPMjAyNjA2MTUwMzQy
# MThaGA8yMDI2MDYxNjAzNDIxOFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7dnz
# GgIBADAHAgEAAgIqJDAHAgEAAgITXDAKAgUA7dtEmgIBADA2BgorBgEEAYRZCgQC
# MSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqG
# SIb3DQEBCwUAA4IBAQBQIiGuOtP1dVdSspYJDe95CTDeVVI0I6y2SClh1+0SgSc6
# Z+VGyKWXv8YoC6p+BndHXStsjbb0nE7l6fwykOJJYTMZPDfTZw6HueTqxPozkObi
# b1oxX4Z3tZWvpH9g1vWWeyyrG0lCIVreG6VLgxohmn0BMyPe0m0Ci6CNdaK/dN8Q
# tsNAwZmavgNiPCyP/uOgUB13KLY+DE09wIPUQHKORr4spm1O7EG7+ZtyOwHU61xq
# S6eCHakUOeK8PqWVfmzP7Xdn9FY+QSD/U3npXi7ARhy0uiTGDUX27Rh2O0JGsvZF
# TI+Ky5D6Do6h6A0aPj2jjmxB2G1KfDZ/VigfOdSDMA0GCSqGSIb3DQEBAQUABIIC
# ACxikZREj2HNpIv5lJ9RpdLQPcdwSTt4WJyhuTo7IHIEDC7yIGAzdZ/UxVQa2Xrd
# Unj0XNjh1AezTcbpHVUbIuLqRaR1BgqYc+KQf68jYQIKSYmXh8FoIvEpZ4Js689v
# XvR6MkQ5HaSjkiQSBlnltUTANv+XaN4Z2TFju6BDdNjbBTkXVWv2Bs6EEU5qQz03
# 9FxmWki/6eBTKXrmA7hzdssRA0ls65qSz+ypl42zUkIAplpiRWIT0hDL/tE9Qi/n
# Hm7a/a2K+IMq94DDSTQWmPyYpUCcKj4wWNWHAVQtB/8mYg4KZjL/SOTrMqA6/agl
# 6N+292D4i5iY2+g3RVVgxOF8MghrPa8hgoC92Ah2n1VpuNGkAo41/UWo+rZVLeki
# HQyGu77WA/cPnGPcHDd0K8aFo0SYBIWrdVCWPcgaZIwxmrx/o1rnAOzrWAnIEduQ
# uT2YS0BHonKy+fm6OMP3HPQn4sbyX0ehRa0QWNan0v+8cQ/GUpIwpVUAnrEtxZek
# R/618EGngzlBFqSQMN3EojqVQ1d56Osw0BrlGWo4VaBZTZ4Fmg7WO1Fk4G42J+Ej
# Gd9XOPHy8YoPFkHwCYS9KkeIRDhArR1fKL14AprnNEROZyH/AWF18AgwFAljDRGL
# WYwQ5azGr9R0Z32jsUsOKRLYEav2mpEU/EgVdbfse6z7
# SIG # End signature block
