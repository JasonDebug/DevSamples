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

        Write-Host "Running 'certutil -urlfetch -verify `"$CertOutputFile`"'"

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

    Write-Host "Connecting to '$Endpoint' on port $Port..."
    
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBS7Ww3r7vs66Qc
# gDFp1pJ2yNI8SgPkJr1kyQZx833smaCCIgIwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggauMIIElqADAgECAhMzAAHNfVAY
# xyz8NXwKAAAAAc19MA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwHhcNMjYwNjA5MTgzMDE5WhcNMjYwNjEy
# MTgzMDE5WjBwMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmEx
# FDASBgNVBAcTC01vdW50IEhvbGx5MRgwFgYDVQQKEw9KYXNvbiBTbGF1Z2h0ZXIx
# GDAWBgNVBAMTD0phc29uIFNsYXVnaHRlcjCCAaIwDQYJKoZIhvcNAQEBBQADggGP
# ADCCAYoCggGBAIYLzps7cN+TPOr3y5bxAg2QAzShih9W0CuY42A2w+jS0VOLKhXx
# oE8RpZw2LHghhSNFEHGlqkw+pPsE9F/Rwt2uRrhzQAQu4gAErrXJqCe4jQDu/DWB
# HYmqrCQqTH+62wuk7SiaN13fSKnQm+9MGgybpnmqRBXZUjB+6tee5NV/2cEPnNrU
# GK0BbT841/Rtb8WNOgNJNT77Fqbp0P2xZyNyY4v0RqS/NcWLNP5CvvP0KYLZ0zxc
# KMreVadJqlzbMG2aASaMyTQvXw1QteGKBGMznClrz3FjCG12ilsQXwHxG/WKrsrZ
# TzjMGQkRzzMHOms6ZZ+WC1gQFLYzPv8cPQybqz5ONT02jVyHfbzaCTnqkG3yLWqp
# mZUvjMNEEnUth6uvJz3g1GP3iR9qvAWjsUJ+qGxYTojPH4I+Nkt+KJvsa6ulJDJ9
# tIRNTZGxGbmCXBgpu1gDcEmoNfPEPS8xJp6IJmFA8VVbklWSpje4f19q7gH99e2o
# +tD0kRNWmuLldwIDAQABo4IB1TCCAdEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E
# BAMCB4AwPAYDVR0lBDUwMwYKKwYBBAGCN2EBAAYIKwYBBQUHAwMGGysGAQQBgjdh
# gt2s5lWC0P7oIoH92NY046SlYzAdBgNVHQ4EFgQU0wf5AIzlJH8QGh8ilTEKmdoL
# M1QwHwYDVR0jBBgwFoAUa16lNMMFxWJKIVqOq3NgYtSsY4UwZwYDVR0fBGAwXjBc
# oFqgWIZWaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9z
# b2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMy5jcmwwdAYI
# KwYBBQUHAQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEVPQyUyMENBJTIwMDMuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUF
# BwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3Np
# dG9yeS5odG0wDQYJKoZIhvcNAQEMBQADggIBAGRPK2tyxiqDtAAe9sgQg7qDS9aF
# sbSzFI0BA8SvgNXvQFZzHrTGgZFeOvFymTTJ3DF47ysgmSGWokPfNpXRRAihXoB0
# IEkKlZqYM+uSyzwCudu44HWaRREHEOmuzzPUKfixhYj4ajB4SyMnyilbcMvuIJBt
# 2UydcrGsgupyiJmh3wtUq6aRTQSHHYiYXBi+YhM2UrQ0igitpZmb/jYK6lkiWf8E
# WllBD4NTVLiVNjbiL/J6OPliAC3Raf5ArObODCjx09lFBEZ9hsaBfVWXRzY4TcMB
# dtUltw0bSFNiHzh1B5utWrI+7aGP85xQhWLKdRZprP6ZdH1uOPkJ/Vpd5gv5jyOI
# O4IYS//5WyN/13LJT1EMDU4+UutHN+dZ99GLtPl/K0fsFz40xQscJlMum8URvBwh
# Kh8OGx1SrdFA/AKpoYwD8xmiVMogneBjVEzZkaheia2I5DUXGgOwM7WW9ZFieeT+
# rUW+Ur+VhP3tIRkyYCOTa7o8Y7iHi5Zog/ITsW9aviKpRjjKYZKeBjNQj2GLgQXm
# kzBLBKxP7MWEnbOq13G7Uq6DNam2Bhi9WRu7hUp4TwyF+EUzoLw6rW2FWMkX98Ib
# qcU0MKyCUzaALt/7NW9n6vIEgDRJeNLgj6rAn+VMp0toxFWfQdYfPUgcbLXtSuYP
# J9WiZUvbjgwW/bOEMIIGrjCCBJagAwIBAgITMwABzX1QGMcs/DV8CgAAAAHNfTAN
# BgkqhkiG9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1Mg
# RU9DIENBIDAzMB4XDTI2MDYwOTE4MzAxOVoXDTI2MDYxMjE4MzAxOVowcDELMAkG
# A1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQHEwtNb3Vu
# dCBIb2xseTEYMBYGA1UEChMPSmFzb24gU2xhdWdodGVyMRgwFgYDVQQDEw9KYXNv
# biBTbGF1Z2h0ZXIwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCGC86b
# O3Dfkzzq98uW8QINkAM0oYofVtArmONgNsPo0tFTiyoV8aBPEaWcNix4IYUjRRBx
# papMPqT7BPRf0cLdrka4c0AELuIABK61yagnuI0A7vw1gR2JqqwkKkx/utsLpO0o
# mjdd30ip0JvvTBoMm6Z5qkQV2VIwfurXnuTVf9nBD5za1BitAW0/ONf0bW/FjToD
# STU++xam6dD9sWcjcmOL9EakvzXFizT+Qr7z9CmC2dM8XCjK3lWnSapc2zBtmgEm
# jMk0L18NULXhigRjM5wpa89xYwhtdopbEF8B8Rv1iq7K2U84zBkJEc8zBzprOmWf
# lgtYEBS2Mz7/HD0Mm6s+TjU9No1ch3282gk56pBt8i1qqZmVL4zDRBJ1LYerryc9
# 4NRj94kfarwFo7FCfqhsWE6Izx+CPjZLfiib7GurpSQyfbSETU2RsRm5glwYKbtY
# A3BJqDXzxD0vMSaeiCZhQPFVW5JVkqY3uH9fau4B/fXtqPrQ9JETVpri5XcCAwEA
# AaOCAdUwggHRMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMDwGA1UdJQQ1
# MDMGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhsrBgEEAYI3YYLdrOZVgtD+6CKB/djW
# NOOkpWMwHQYDVR0OBBYEFNMH+QCM5SR/EBofIpUxCpnaCzNUMB8GA1UdIwQYMBaA
# FGtepTTDBcViSiFajqtzYGLUrGOFMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVy
# aWZpZWQlMjBDUyUyMEVPQyUyMENBJTIwMDMuY3JsMHQGCCsGAQUFBwEBBGgwZjBk
# BggrBgEFBQcwAoZYaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAz
# LmNydDBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqG
# SIb3DQEBDAUAA4ICAQBkTytrcsYqg7QAHvbIEIO6g0vWhbG0sxSNAQPEr4DV70BW
# cx60xoGRXjrxcpk0ydwxeO8rIJkhlqJD3zaV0UQIoV6AdCBJCpWamDPrkss8Arnb
# uOB1mkURBxDprs8z1Cn4sYWI+GoweEsjJ8opW3DL7iCQbdlMnXKxrILqcoiZod8L
# VKumkU0Ehx2ImFwYvmITNlK0NIoIraWZm/42CupZIln/BFpZQQ+DU1S4lTY24i/y
# ejj5YgAt0Wn+QKzmzgwo8dPZRQRGfYbGgX1Vl0c2OE3DAXbVJbcNG0hTYh84dQeb
# rVqyPu2hj/OcUIViynUWaaz+mXR9bjj5Cf1aXeYL+Y8jiDuCGEv/+Vsjf9dyyU9R
# DA1OPlLrRzfnWffRi7T5fytH7Bc+NMULHCZTLpvFEbwcISofDhsdUq3RQPwCqaGM
# A/MZolTKIJ3gY1RM2ZGoXomtiOQ1FxoDsDO1lvWRYnnk/q1FvlK/lYT97SEZMmAj
# k2u6PGO4h4uWaIPyE7FvWr4iqUY4ymGSngYzUI9hi4EF5pMwSwSsT+zFhJ2zqtdx
# u1KugzWptgYYvVkbu4VKeE8MhfhFM6C8Oq1thVjJF/fCG6nFNDCsglM2gC7f+zVv
# Z+ryBIA0SXjS4I+qwJ/lTKdLaMRVn0HWHz1IHGy17UrmDyfVomVL244MFv2zhDCC
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
# Q0EgMDMCEzMAAc19UBjHLPw1fAoAAAABzX0wDQYJYIZIAWUDBAIBBQCgXjAQBgor
# BgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG
# 9w0BCQQxIgQgQSt2ZZ9GBc6q72vm9ZYTHaspMstUN6RXngux4QwTpAgwDQYJKoZI
# hvcNAQEBBQAEggGADbcmArrE/J7f8FU7BW/ZqmthXyykVmhtCpGtmtVUycF1cwdY
# 12ukU/JjXBsApktXUge2XFBCalTvVjQPF3LJzSJXjqzg2W755+m1ZYlYOXKLuKQe
# k8CG1jtFsPUQfniXvxFJ192lyAUf4q746N5OxzxCHpQh679JcXrihGPsoC+f/803
# O9c3t5R/27d957lsin0Pi8HASiEYgndBrpAMZJRBwnVEwzM2iYUDP5wu2j28Z2LQ
# eDM+XHLMlAbNjTqL7tb/Ffh8f521j/ItiH42PLSoD6Ej62kLcAQ4QrsmO5Uu1Itu
# kMohHnJ6VuwvCpX29bcfANE8srFNDCAtEoOuHS4QuuFo15b3sDCoiSbLkzERevw9
# j+8OluKXmqQOmHI8OaFWx04vuM/vNClnWYLz/RSN3Ve3L8RGahTzlhudVOf67LqO
# vcIoncqKH3fozrMSvAda6wAjyqbM55gYGb0FGXWAU14NGinQW3kqdLPOeLfwnzsm
# qP6gUlOpdz8Zoc9soYIYETCCGA0GCisGAQQBgjcDAwExghf9MIIX+QYJKoZIhvcN
# AQcCoIIX6jCCF+YCAQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEE
# oIIBUQSCAU0wggFJAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIEIL
# F3vUec+LjZkEBbWVRYtBOtmBAXAQMmQOGHZD7HbSAgZqF2YmJtMYEzIwMjYwNjEx
# MTU0NDE1LjAzOVowBIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJh
# dGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo3QTAwLTA1RTAtRDk0NzE1
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
# r1nJfiWG2GwYe6ZoAF1bMIIHlzCCBX+gAwIBAgITMwAAAFhlzes/odf80gAAAAAA
# WDANBgkqhkiG9w0BAQwFADBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBU
# aW1lc3RhbXBpbmcgQ0EgMjAyMDAeFw0yNTEwMjMyMDQ2NTVaFw0yNjEwMjIyMDQ2
# NTVaMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYD
# VQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hp
# ZWxkIFRTUyBFU046N0EwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQ
# dWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAnXg0pHaQ7PVAlln+HZZrJFcLoKbekhW1yL+QNBUg
# FFUsjZIKaqqN4oIJsJM3ps0rJNSO7ndCNRuZDX2Wgur3Ak77eXrloBXqZmO6ZVXe
# DNRCLldW4A0/NfjzJ7XXkdEhjr81ghXEpR7zC+wbaNN+sPSxzLAZBeibDFP7Xws5
# wX0ZtIsN1a2+Xq5bvWp3kRMytwskTjunRgeLZL/tBp237JVdRPFAQ9jYRKpCqUBo
# /v1xjBLRCV3PalKjnGfb3MN4U7jVyqifFHShcnW5CERRoBmUa6sygDzFSr8e3g93
# TPNLFUivUE0GmLfbX5ceD1Gt1FcZ6x/JLVATzk5+BWHbMxwJIVkVPTqSSMjQ6KTK
# dcnq3pH0c4AFJp/glvcpq0U9fzZIjJGGvdpishlRl77RQtUhSjxHvCn3LC/xqQQw
# OHSQDsGh6NX2D0RfsSyEtTAByAae+2w1HByTDTcmlTNLEuQLeCj1gNBdIWj0WOYy
# DtjjQ/8iTWY6ey1vb9qHljIj5HgIndT5P9MYk2Vg2e7hKUZNBNbA/hsgBsuoZ+IX
# 89WvjEN9abF91S4OJVuinmKsLO/MLbnl7ikuD0dN6oA0YewyDQncs12sM9HOtu72
# QA/TZlefvW8r9xtMXAYoQlcGjsk8W4Uc7cfqVqbIPjdoc8ZxBzLcXcVyP4p5cyLw
# vkMCAwEAAaOCAcswggHHMB0GA1UdDgQWBBRyjU3Fer4VxXJ+hjPcRJnxnRIJsDAf
# BgNVHSMEGDAWgBRraSg6NS9IY0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6Bd
# hltodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkG
# CCsGAQUFBwEBBG0wazBpBggrBgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1l
# c3RhbXBpbmclMjBDQSUyMDIwMjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYB
# BAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcN
# AQEMBQADggIBAHvrxIiVF1iHcXvxrJTCD8eOtbPUbK9x+Lz70iYehh+G0UoOMcMf
# 04QD6tQPTeZ5HhGETkcn0raDJ5NpfbRBuKEH31rxbZK97o12KRDNJ3Nu4ePaUIpH
# /TcWz8PLVOCECywSxbEgEG20kyydGc46c591tXzpfkJDckjoYrypaerdeQLRQH9L
# aoTYZfdAzMo+Dy0O1DzFJkF5YnsmAM8lt9r1NtXdFjdbFMCbV5dau64mV22s186A
# 8Umi+l239+Ue0cbJQIykWhIlhhWhxQgoksqHz7kp2GFZAAeySTmIOQOWyXOA8JA8
# TISJyn3JDOgStv583P3V0QSALT6JXDCW26FV208VGJMzkv0S22iOTZJ/oamTpk8R
# zD8oWT8pfbe1q/k/bxPiXYRbzps96a5YOko7n0Vdo61DOJhL/mhk01Y348gq6vhG
# /VTcdGHh1rCkwOM05B35AZZq9AtPpfRzJinrHzzGRx+r6fD3ccYMPMMX/Nwd2irz
# rph172fQcSf1fMwvwIhmfH4GWJJ+mf1HA6uXoAOVByckguXvlj8gPi7T2ES6RU8+
# QssfqTNTJKjsBheWKWv2W4ESVen2L7lCz7i79FhA+0kp0yXJnYwdzWS0ovTINULI
# NmzVyMcSUm5WuVf8YZ33cAud2Opr6N1+RuLZDavDvjiehlI5dH+GEy56MYIHQzCC
# Bz8CAQEweDBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBp
# bmcgQ0EgMjAyMAITMwAAAFhlzes/odf80gAAAAAAWDANBglghkgBZQMEAgEFAKCC
# BJwwEQYLKoZIhvcNAQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAcBgkqhkiG9w0BCQUxDxcNMjYwNjExMTU0NDE1WjAvBgkqhkiG9w0BCQQxIgQg
# EikCKv6Jd8UOd+QwLm6+NuJ1CsXqVaFYLpOxwuIZmZgwgbkGCyqGSIb3DQEJEAIv
# MYGpMIGmMIGjMIGgBCDFIlS7sgfQ+wAo1cWbWz+WN69VBds58hbran919aLocTB8
# MGWkYzBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcg
# Q0EgMjAyMAITMwAAAFhlzes/odf80gAAAAAAWDCCA14GCyqGSIb3DQEJEAISMYID
# TTCCA0mhggNFMIIDQTCCAikCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0EwMC0wNUUw
# LUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBp
# bmcgQXV0aG9yaXR5oiMKAQEwBwYFKw4DAhoDFQCdZHkb26ercF2O62vCdZUfUSvE
# XKBnMGWkYzBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBp
# bmcgQ0EgMjAyMDANBgkqhkiG9w0BAQsFAAIFAO3VAlEwIhgPMjAyNjA2MTEwOTQ1
# NTNaGA8yMDI2MDYxMjA5NDU1M1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7dUC
# UQIBADAHAgEAAgIUxjAHAgEAAgITJjAKAgUA7dZT0QIBADA2BgorBgEEAYRZCgQC
# MSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqG
# SIb3DQEBCwUAA4IBAQBFU10+Ibvhkul2lA6Dzhpt3oRAZ0xGKAxJar6eJDz6RYyf
# 2fFUCHOXQfoLbnAZ4ZFFzKE+aIchqnTxoxaK4vlFl+5YwA7aGUBwGSa8jlDXgGlV
# RPlS1rOKQx2t4w0J51QVKdtCV8DYzHZDlbfdY7FZVQJ0I/CU3RaxGnIf7PP++g5X
# Z/oa+XqdvXJACfesFeULh2cvPfOrMhk20wi6yArRoZZ+SvxoyVGuv9ez80hwAUTJ
# Y1URVStaTLxxpl4fBGRuYG+4GO+k4qRbWJO9GcJt4yHh92eP7OgVBa4+y6rPO90E
# F3BGM0jBA54Li6/DGEcTGnI8IDOznu8PA/QUUwPUMA0GCSqGSIb3DQEBAQUABIIC
# AIcitij/YGuwQA3T3tyJFoBy25OLdtC8rbBrt9lBo2R621wEw/LeZWV0lDkgQRfX
# rEHwqtpf7stn16kzsiafaRTs1Xl5FgP7zwxiI30UXgEL2fhWp4iFu8o+1VBthuY/
# 9Oiav4i/kLsJbN9peropHFbt9MN/MDBUbX6atqQ5lAKRyJ7TK/TiaI1Lbo4B7tF4
# kTH0dX8IrHYQifzRpubxH3VLNscT290xZVaOk++GNLxWWhl92CRuLOaootVWUQnV
# thFKCC0A85Xg56TselCM9SNmcG0AHlV5ZLMEMmbGN8G1cRWUI7fyDzVmWYty/KS+
# gCBpsEP9IQv/n6NyU/8eqtLJ/NSFRZCo76eeZ0fLcxae6gZ9CSXPrcfng+tqdu9w
# zWoQS295ljOynynyaCYYoO8N9nrHAMhw/iepCH7UJXDbFKpApiSKzceiHVaCwUbp
# P/mOSEcjRyaILdobNYnSKSpDlOnklnuqvc+sgXPssrpIQfMj/tgL35uJUU/P1KhT
# p2VdjeDyxPxII7Cqw9ztLQiCaPJQLtkYL73xNGwa9vS6ELKqgpUXJ82N0WgAEg0T
# Wb0BgAGXsoJejItA65oib6FSoyd8/Epd7ogMYaPs/0La4RbzDJDTWj4M/xEMSlsN
# ig5+7yIMHWX2K3u1IH7mOP0/2FK3OKJQ/8Duyc/iIPPi
# SIG # End signature block
