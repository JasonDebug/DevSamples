/*********************************************************************************
* MIT License                                                                    *
*                                                                                *
* Copyright (c) 2022 Jason                                                       *
*                                                                                *
* Permission is hereby granted, free of charge, to any person obtaining a copy   *
* of this software and associated documentation files (the "Software"), to deal  *
* in the Software without restriction, including without limitation the rights   *
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      *
* copies of the Software, and to permit persons to whom the Software is          *
* furnished to do so, subject to the following conditions:                       *
*                                                                                *
* The above copyright notice and this permission notice shall be included in all *
* copies or substantial portions of the Software.                                *
*                                                                                *
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     *
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       *
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    *
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         *
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  *
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  *
* SOFTWARE.                                                                      *
**********************************************************************************/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DumpRemoteCert
{
    internal class Program
    {
        static void ShowUsage()
        {
            var allProtocols = Enum.GetNames(typeof(SslProtocols));

            Console.WriteLine($"Usage: DumpRemoteCert.exe <endpoint[:port]> [port] [-ForceProtocolVersion {string.Join(", ", allProtocols)}]");
            Console.WriteLine("Examples:");
            Console.WriteLine("  DumpRemoteCert.exe example.com:443");
            Console.WriteLine("  DumpRemoteCert.exe example.com 443 -ForceProtocolVersion Tls12,Tls13");
        }

        /*
        https://learn.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols
        Note regarding "Default" setting -- Despite the name of this field, SslStream does not use it as a default except
        under special circumstances, and is considered obsolete. Use "None" to allow the OS to choose.
        */
        static SslProtocols ParseProtocols(string input)
        {
            var tokens = input.Split(',', StringSplitOptions.RemoveEmptyEntries);
            SslProtocols result = SslProtocols.None;

            foreach (var token in tokens)
            {
                if (Enum.TryParse(typeof(SslProtocols), token.Trim(), ignoreCase: true, out var value))
                {
                    result |= (SslProtocols)value;
                }
                else
                {
                    Console.Error.WriteLine($"Invalid SSL protocol: '{token}'");
                    Environment.Exit(1);
                }
            }

            return result;
        }

        [STAThread]
        static void Main(string[] args)
        {
            string endpoint = string.Empty;
            int port = 443;
            SslProtocols forcedProtocols = SslProtocols.None;

            // In case someone tries to use a URL
            if (args.Length == 0 ||
                args[0].Contains("\\") ||
                args[0].Contains("/"))
            {
                ShowUsage();
                return;
            }

            var argQueue = new Queue<string>(args);

            while (argQueue.Count > 0)
            {
                var arg = argQueue.Dequeue();

                if (arg.StartsWith("-ForceProtocolVersion", StringComparison.OrdinalIgnoreCase))
                {
                    string val = string.Empty;

                    // Accept = and : as well
                    if (arg.Contains('='))
                    {
                        val = arg.Split('=', 2)[1];
                    }
                    else if (arg.Contains(':'))
                    {
                        val = arg.Split(':', 2)[1];
                    }
                    else if (argQueue.Count > 0)
                    {
                        val = argQueue.Dequeue();
                    }

                    if (!string.IsNullOrEmpty(val))
                    {
                        forcedProtocols = ParseProtocols(val);
                    }
                    else
                    {
                        Console.Error.WriteLine("Missing value for -ForceProtocolVersion");
                        return;
                    }
                }
                else if (string.IsNullOrEmpty(endpoint))
                {
                    // server:port or server port?
                    if (arg.Contains(":"))
                    {
                        var parts = arg.Split(":");
                        endpoint = arg.Split(':')[0];
                        port = int.Parse(arg.Split(':')[1]);
                    }
                    else
                    {
                        endpoint = arg;
                    }
                }
                else if (int.TryParse(arg, out int parsedPort))
                {
                    port = parsedPort;
                }
                else
                {
                    Console.Error.WriteLine($"Unrecognized argument: {arg}");
                    ShowUsage();
                    return;
                }
            }

            try
            {
                Console.WriteLine($"Connecting to '{endpoint}' on port {port}...");

                if (forcedProtocols != SslProtocols.None)
                {
                    Console.WriteLine($"Forcing protocol version(s): {forcedProtocols}");
                }

                using (var client = new TcpClient(endpoint, port))
                {
                    using (var ssl = new SslStream(client.GetStream(), false, streamCallback))
                    {
                        // Trigger the callback
                        ssl.AuthenticateAsClient(endpoint, null, forcedProtocols, true);

                        ssl.Close();
                        client.Close();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failure. {ex.ToString()}");
            }
        }

        // Dump the certificate info.  Write the given certificate to disk
        // and dump with certutil -urlfetch -verify
        private static void dumpCertInfo(X509Certificate certificate)
        {
            var x509 = (X509Certificate2)certificate;
            var tempFilename = Path.GetTempFileName().Replace(".tmp", ".cer");
            var certBytes = x509.Export(X509ContentType.Cert);
            System.IO.File.WriteAllBytes(tempFilename, certBytes);

            Console.WriteLine($"Certificate written to: {tempFilename}");
            Console.WriteLine();

            // At-a-glance info:
            Console.WriteLine($"Subject: {x509.Subject}");
            Console.WriteLine($"Validity period: {x509.NotBefore} to {x509.NotAfter}");

            var sanExtension = x509.Extensions["2.5.29.17"];
            if (sanExtension != null)
            {
                var sanData = new AsnEncodedData(sanExtension.Oid, sanExtension.RawData);
                var sanStrings = sanData.Format(true);

                Console.WriteLine("Subject alternative names (SAN):");
                Console.WriteLine(sanStrings);
            }
  
            Console.WriteLine($"Running 'certutil -urlfetch -verify {tempFilename}'");
            using (var process = new Process())
            {
                process.StartInfo = new ProcessStartInfo()
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    FileName = "cmd.exe",
                    Arguments = $@"/C certutil -urlfetch -verify {tempFilename}",
                    RedirectStandardError = true,
                    RedirectStandardOutput = true
                };
                process.Start();

                var certutil = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Dump the certutil output
                Console.WriteLine(certutil);

                // Open the certificate
                Process.Start(new ProcessStartInfo
                {
                    FileName = tempFilename,
                    UseShellExecute = true      // Defaults to false in .NET 5+
                });
            }
        }

        private static bool streamCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            if (null != certificate)
            {
                dumpCertInfo(certificate);
            }
            else
            {
                Console.WriteLine("No certificate found in SSL stream.");
            }

            return true;
        }
    }
}
