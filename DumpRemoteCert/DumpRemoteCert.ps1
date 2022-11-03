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
    [int]$Port = 636,

    [string]$CertOutputFile,
    [switch]$SkipCertPopup
)

Process
{
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

        Write-Host "Running 'certutil -urlfetch -verify $CertOutputFile'"

        ## Start-Process output does not display correctly
        ## Export to file and read it in and we'll have broken newlines
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.CreateNoWindow = $true
        $ProcessInfo.FileName = "certutil.exe"
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.Arguments = "-urlfetch -verify $CertOutputFile"
    
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
        $ssl = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false, $dumpCertInfo
        $ssl.AuthenticateAsClient($Endpoint)
    }
    catch
    {
        Write-Host $error
    }
}
