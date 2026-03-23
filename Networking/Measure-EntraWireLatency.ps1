##################################################################################
# MIT License                                                                    #
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

<#

.\Measure-EntraWireLatency.ps1 -TenantId your-tenant-guid -Iterations 20 -OutputCsv .\entra-wire-latency.csv

#>

param(
  [Parameter(Mandatory = $true)]
  [string]$TenantId,
  [int]$Iterations = 10,
  [int]$PauseMs = 500,
  [string]$OutputCsv = ".\entra-wire-latency.csv",
  [switch]$TestCert
)

$ErrorActionPreference = "Stop"
$DumpRemoteCertScript = ".\DumpRemoteCert.ps1"

function Resolve-LocalPath {
  param([Parameter(Mandatory = $true)][string]$Path)

  if ([System.IO.Path]::IsPathRooted($Path)) {
    return $Path
  }

  if ($PSScriptRoot) {
    return (Join-Path $PSScriptRoot $Path)
  }

  return (Join-Path (Get-Location).Path $Path)
}

function Ensure-DumpRemoteCertScript {
  param([Parameter(Mandatory = $true)][string]$ScriptPath)

  if (Test-Path -LiteralPath $ScriptPath) {
    return
  }

  $downloadUrl = "https://raw.githubusercontent.com/JasonDebug/DevSamples/main/Security/Certificates/DumpRemoteCert/DumpRemoteCert.ps1"
  Write-Host "DumpRemoteCert script not found. Downloading from $downloadUrl"

  $scriptDir = Split-Path -Parent $ScriptPath
  if (-not (Test-Path -LiteralPath $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
  }

  Invoke-WebRequest -Uri $downloadUrl -OutFile $ScriptPath -UseBasicParsing
  Write-Host "Saved DumpRemoteCert script to: $ScriptPath"
}

function Invoke-CertTest {
  param(
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [Parameter(Mandatory = $true)][string[]]$Hosts
  )

  $uniqueHosts = $Hosts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
  foreach ($HostName in $uniqueHosts) {
    Write-Host "Running cert test for host: $HostName"
    & $ScriptPath -Endpoint $HostName
  }
}

function Measure-DnsMs {
  param([string]$HostName)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $null = Resolve-DnsName -Name $HostName -Type A -ErrorAction Stop
  } catch {
    $sw.Stop()
    return @{ Success = $false; Ms = $sw.Elapsed.TotalMilliseconds; Error = $_.Exception.Message }
  }
  $sw.Stop()
  return @{ Success = $true; Ms = $sw.Elapsed.TotalMilliseconds; Error = $null }
}

function Measure-TcpConnectMs {
  param([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 10000)
  $client = New-Object System.Net.Sockets.TcpClient
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $task = $client.ConnectAsync($HostName, $Port)
    if (-not $task.Wait($TimeoutMs)) {
      throw "TCP connect timeout after $TimeoutMs ms"
    }
  } catch {
    $sw.Stop()
    $client.Dispose()
    return @{ Success = $false; Ms = $sw.Elapsed.TotalMilliseconds; Error = $_.Exception.Message }
  }
  $sw.Stop()
  $client.Dispose()
  return @{ Success = $true; Ms = $sw.Elapsed.TotalMilliseconds; Error = $null }
}

function Measure-TlsHandshakeMs {
  param([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 10000)

  $tcp = New-Object System.Net.Sockets.TcpClient
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $tcp.ReceiveTimeout = $TimeoutMs
    $tcp.SendTimeout = $TimeoutMs

    $task = $tcp.ConnectAsync($HostName, $Port)
    if (-not $task.Wait($TimeoutMs)) {
      throw "TCP connect timeout before TLS after $TimeoutMs ms"
    }

    $netStream = $tcp.GetStream()
    $netStream.ReadTimeout = $TimeoutMs
    $netStream.WriteTimeout = $TimeoutMs
    $ssl = New-Object System.Net.Security.SslStream($netStream, $false, { $true })

    # Use synchronous handshake to avoid Task.Wait aggregate wrapper behavior.
    $ssl.AuthenticateAsClient($HostName)
    $sw.Stop()

    $ssl.Dispose()
    $netStream.Dispose()
    $tcp.Dispose()

    return @{ Success = $true; Ms = $sw.Elapsed.TotalMilliseconds; Error = $null }
  } catch {
    $sw.Stop()
    $tcp.Dispose()
    return @{ Success = $false; Ms = $sw.Elapsed.TotalMilliseconds; Error = $_.Exception.Message }
  }
}

function Measure-HttpMs {
  param([string]$Url, [int]$TimeoutSec = 30)

  $handler = New-Object System.Net.Http.HttpClientHandler
  $client = New-Object System.Net.Http.HttpClient($handler)
  $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)

  try {
    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    $ttfbMs = $sw.Elapsed.TotalMilliseconds

    $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $buffer = New-Object byte[] 8192
    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) { }

    $sw.Stop()
    $totalMs = $sw.Elapsed.TotalMilliseconds
    $status = [int]$resp.StatusCode

    $stream.Dispose()
    $resp.Dispose()
    $req.Dispose()
    $client.Dispose()

    return @{
      Success = $true
      StatusCode = $status
      TtfbMs = $ttfbMs
      TotalMs = $totalMs
      Error = $null
    }
  } catch {
    $client.Dispose()
    return @{
      Success = $false
      StatusCode = $null
      TtfbMs = $null
      TotalMs = $null
      Error = $_.Exception.Message
    }
  }
}

function Test-Endpoint {
  param(
    [string]$EndpointName,
    [string]$Url,
    [int]$Iteration
  )

  $uri = [System.Uri]$Url
  $hostName = $uri.Host

  $dns = Measure-DnsMs -HostName $hostName
  $tcp = Measure-TcpConnectMs -HostName $hostName -Port 443
  $tls = Measure-TlsHandshakeMs -HostName $hostName -Port 443
  $http = Measure-HttpMs -Url $Url -TimeoutSec 30

  return [PSCustomObject]@{
    TimestampUtc   = (Get-Date).ToUniversalTime().ToString("o")
    Iteration      = $Iteration
    EndpointName   = $EndpointName
    Url            = $Url
    Host           = $hostName

    DnsSuccess     = $dns.Success
    DnsMs          = [math]::Round(($dns.Ms | ForEach-Object { $_ }), 2)
    DnsError       = $dns.Error

    TcpSuccess     = $tcp.Success
    TcpConnectMs   = if ($tcp.Ms -ne $null) { [math]::Round($tcp.Ms, 2) } else { $null }
    TcpError       = $tcp.Error

    TlsSuccess     = $tls.Success
    TlsHandshakeMs = if ($tls.Ms -ne $null) { [math]::Round($tls.Ms, 2) } else { $null }
    TlsError       = $tls.Error

    HttpSuccess    = $http.Success
    HttpStatusCode = $http.StatusCode
    HttpTtfbMs     = if ($http.TtfbMs -ne $null) { [math]::Round($http.TtfbMs, 2) } else { $null }
    HttpTotalMs    = if ($http.TotalMs -ne $null) { [math]::Round($http.TotalMs, 2) } else { $null }
    HttpError      = $http.Error
  }
}

$metadataUrl = "https://login.microsoftonline.com/$TenantId/v2.0/.well-known/openid-configuration"
$retries = 3

Write-Host "Fetching metadata to discover keyset URI..."
for ($attempt = 1; $attempt -le $retries; $attempt++) {
  try {
    $metaObj = Invoke-RestMethod -Uri $metadataUrl -Method Get -TimeoutSec 30 -ErrorAction Stop
    $jwksUrl = $metaObj.jwks_uri

    if ($metaObj -and $metaObj.jwks_uri) {
        break
    }
  }
  catch {
    Write-Host "Attempt $attempt/$retries failed:" -ForegroundColor Yellow
    Write-Host "Error: $($_.Exception.Message)"
  }
}

if (-not $jwksUrl) {
  Write-Host "Could not discover keyset URI from metadata. Exiting." -ForegroundColor Red
  return
}

Write-Host "Metadata URL: $metadataUrl"
Write-Host "JWKS URL: $jwksUrl"

if ($TestCert) {
  $dumpScriptPath = Resolve-LocalPath -Path $DumpRemoteCertScript
  Ensure-DumpRemoteCertScript -ScriptPath $dumpScriptPath

  $metadataHost = ([System.Uri]$metadataUrl).Host
  $jwksHost = ([System.Uri]$jwksUrl).Host
  Invoke-CertTest -ScriptPath $dumpScriptPath -Hosts @($metadataHost, $jwksHost)
}

Write-Host "Running $Iterations iterations..."

$results = New-Object System.Collections.Generic.List[object]

for ($i = 1; $i -le $Iterations; $i++) {
  Write-Verbose "Iteration $i/$Iterations - metadata"
  Write-Host "." -NoNewline
  $results.Add((Test-Endpoint -EndpointName "metadata" -Url $metadataUrl -Iteration $i))

  Write-Verbose "Iteration $i/$Iterations - jwks"
  Write-Host "." -NoNewline
  $results.Add((Test-Endpoint -EndpointName "jwks" -Url $jwksUrl -Iteration $i))

  Start-Sleep -Milliseconds $PauseMs
}

Write-Host "$Iterations completed. Saving results to CSV..."

$results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Saved raw results to $OutputCsv"
Write-Host ""

function Get-P95Value {
  param([object[]]$Values)

  if (-not $Values -or $Values.Count -eq 0) {
    return $null
  }

  $sorted = $Values | Sort-Object
  $index = [math]::Floor(($sorted.Count - 1) * 0.95)
  return [math]::Round([double]$sorted[$index], 2)
}

$summary = $results |
  Group-Object EndpointName |
  ForEach-Object {
    $name = $_.Name
    $group = $_.Group
    $okHttp = $group | Where-Object { $_.HttpSuccess -eq $true -and $_.HttpTotalMs -ne $null }
    $okDns = $group | Where-Object { $_.DnsSuccess -eq $true -and $_.DnsMs -ne $null }
    $okTcp = $group | Where-Object { $_.TcpSuccess -eq $true -and $_.TcpConnectMs -ne $null }
    $okTls = $group | Where-Object { $_.TlsSuccess -eq $true -and $_.TlsHandshakeMs -ne $null }

    [PSCustomObject]@{
      Endpoint       = $name
      Samples        = $okHttp.Count
      AvgDnsMs       = if ($okDns.Count) { [math]::Round((($okDns | Measure-Object DnsMs -Average).Average), 2) } else { $null }
      P95DnsMs       = if ($okDns.Count) { Get-P95Value -Values ($okDns | Select-Object -ExpandProperty DnsMs) } else { $null }
      AvgTcpMs       = if ($okTcp.Count) { [math]::Round((($okTcp | Measure-Object TcpConnectMs -Average).Average), 2) } else { $null }
      P95TcpMs       = if ($okTcp.Count) { Get-P95Value -Values ($okTcp | Select-Object -ExpandProperty TcpConnectMs) } else { $null }
      AvgTlsMs       = if ($okTls.Count) { [math]::Round((($okTls | Measure-Object TlsHandshakeMs -Average).Average), 2) } else { $null }
      P95TlsMs       = if ($okTls.Count) { Get-P95Value -Values ($okTls | Select-Object -ExpandProperty TlsHandshakeMs) } else { $null }
      AvgTtfbMs      = if ($okHttp.Count) { [math]::Round((($okHttp | Measure-Object HttpTtfbMs -Average).Average), 2) } else { $null }
      P95TtfbMs      = if ($okHttp.Count) { Get-P95Value -Values ($okHttp | Select-Object -ExpandProperty HttpTtfbMs) } else { $null }
      AvgTotalMs     = if ($okHttp.Count) { [math]::Round((($okHttp | Measure-Object HttpTotalMs -Average).Average), 2) } else { $null }
      P95TotalMs     = if ($okHttp.Count) { Get-P95Value -Values ($okHttp | Select-Object -ExpandProperty HttpTotalMs) } else { $null }
    }
  }

Write-Host "Samples    = number of successful HTTP requests with valid timing data"
Write-Host "AvgDnsMs   = average DNS resolution time in milliseconds"
Write-Host "P95DnsMs   = 95th percentile DNS resolution time in milliseconds"
Write-Host "AvgTcpMs   = average TCP connect time in milliseconds"
Write-Host "P95TcpMs   = 95th percentile TCP connect time in milliseconds"
Write-Host "AvgTlsMs   = average TLS handshake time in milliseconds"
Write-Host "P95TlsMs   = 95th percentile TLS handshake time in milliseconds"
Write-Host "AvgTtfbMs  = average time to first byte in milliseconds"
Write-Host "P95TtfbMs  = 95th percentile time to first byte in milliseconds"
Write-Host "AvgTotalMs = average total time in milliseconds"
Write-Host "P95TotalMs = 95th percentile total time in milliseconds"

Write-Host "Summary:"
$summary | Format-Table -AutoSize
