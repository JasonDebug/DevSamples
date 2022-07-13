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
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DumpRemoteCert
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string endpoint = null;
            int port = 443;

            // In case someone tries to use a URL
            if (args.Length == 0 ||
                args[0].Contains("\\") ||
                args[0].Contains("/"))
            {
                Console.WriteLine($"Usage: DumpRemoteCert.exe <remoteEndpoint:port> | <remoteEndpoint> <port>");
                Console.WriteLine($"e.g. DumpRemoteCert dc1.contoso.com:636");
                return;
            }

            // server:port or server port?
            if (args[0].Contains(":"))
            {
                endpoint = args[0].Split(':')[0];
                port = int.Parse(args[0].Split(':')[1]);
            }
            else
            {
                endpoint = args[0];

                // Default to 443, typical use case
                if (args.Length > 1)
                {
                    port = int.Parse(args[1]);
                }
            }

            try
            {
                Console.WriteLine($"Connecting to '{endpoint}' on port {port}...");
                using (var client = new TcpClient(endpoint, port))
                {
                    using (var ssl = new SslStream(client.GetStream(), false, streamCallback))
                    {
                        // Trigger the callback
                        ssl.AuthenticateAsClient(endpoint);

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
                Process.Start(tempFilename);
            }
        }

        private static bool streamCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            dumpCertInfo(certificate);
            return true;
        }
    }
}
