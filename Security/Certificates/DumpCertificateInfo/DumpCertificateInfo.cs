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

using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace DumpCertificateInfo
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CATALOG_INFO
        {
            public int cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATCatalogInfoFromContext(
            IntPtr hCatInfo,
            ref CATALOG_INFO psCatInfo,
            uint dwFlags = 0u);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        public const uint ERROR_INSUFFICIENT_BUFFER = 122;

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: DumpCertificateInfo <filename>");
                return;
            }

            if (!GetFileCertificateInfo(args[0]))
            {
                Console.WriteLine("Failed to get certificate information for file: " + args[0]);
            }
        }

        static bool GetFileCertificateInfo(string filePath)
        {
            SafeFileHandle fileToCheck = null;
            try
            {
                fileToCheck = File.OpenRead(filePath)?.SafeFileHandle;

                if (null == fileToCheck)
                {
                    throw new Exception("Unable to get handle for file.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to open file. Error: {ex.Message}");
            }

            // Acquire a handle to the catalog administrator context
            // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadminacquirecontext
            IntPtr hCatAdmin = IntPtr.Zero;
            if (!CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0))
            {
                Console.WriteLine($"CryptCATAdminAcquireContext failed. Error: {Marshal.GetLastWin32Error()}");
                return false;
            }

            // First, call CryptCATAdminCalcHashFromFileHandle to get the hash size
            // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadmincalchashfromfilehandle
            uint hashSize = 0;
            CryptCATAdminCalcHashFromFileHandle(fileToCheck.DangerousGetHandle(), ref hashSize, null, 0);
            if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
            {
                Console.WriteLine($"CryptCATAdminCalcHashFromFileHandle failed to get the buffer size. Error: {Marshal.GetLastWin32Error()}");
                CryptCATAdminReleaseContext(hCatAdmin, 0);
                fileToCheck.Dispose();
                return false;
            }

            // Allocate buffer for the hash using the hash size from the previous call to CryptCATAdminCalcHashFromFileHandle
            var hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle(fileToCheck.DangerousGetHandle(), ref hashSize, hash, 0))
            {
                Console.WriteLine($"CryptCATAdminCalcHashFromFileHandle failed. Error: {Marshal.GetLastWin32Error()}");
                fileToCheck.Dispose();
                return false;
            }

            fileToCheck.Dispose();

            // Display the calculated hash
            Console.WriteLine($"PESHA1 File Hash: {BitConverter.ToString(hash).Replace("-", string.Empty)}");

            // Enumerate the catalog files that contain the specified hash
            // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadminenumcatalogfromhash
            IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero)
            {
                Console.WriteLine($"CryptCATAdminEnumCatalogFromHash failed. Error: {Marshal.GetLastWin32Error()}");
                CryptCATAdminReleaseContext(hCatAdmin, 0);
                return false;
            }

            // Get the catalog information from the context (namely the catalog file path)
            // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatcataloginfofromcontext
            CATALOG_INFO catInfo = new CATALOG_INFO
            {
                cbStruct = Marshal.SizeOf(typeof(CATALOG_INFO))
            };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo))
            {
                Console.WriteLine($"CryptCATCatalogInfoFromContext failed. Error: {Marshal.GetLastWin32Error()}");
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                CryptCATAdminReleaseContext(hCatAdmin, 0);
                return false;
            }

            // Display the catalog file path
            Console.WriteLine($"Catalog File Path: {catInfo.wszCatalogFile}");

            // Verify and display the signature from the catalog file
            // Counter-signatures are not supported in this example
            bool result = VerifyCertificate(catInfo.wszCatalogFile);

            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            CryptCATAdminReleaseContext(hCatAdmin, 0);

            return result;
        }

        // Verify the certificate from the catalog file and display the certificate details
        static bool VerifyCertificate(string catFilePath)
        {
            X509Certificate cert = X509Certificate.CreateFromCertFile(catFilePath);

            if (cert == null)
            {
                Console.WriteLine("Failed to load certificate from catalog file.");
                return false;
            }

            // Display certificate details
            DisplayCertificateInfo(cert);

            // Do the validation
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = DateTime.Now;

            bool isValid = chain.Build(new X509Certificate2(cert));

            foreach (X509ChainStatus status in chain.ChainStatus)
            {
                if (status.Status != X509ChainStatusFlags.NoError)
                {
                    Console.WriteLine($"Chain error: {status.StatusInformation}");
                    isValid = false;
                }
            }

            if (isValid)
                Console.WriteLine("Certificate chain verified successfully.");

            return isValid;
        }

        static void DisplayCertificateInfo(X509Certificate cert)
        {
            X509Certificate2 cert2 = new X509Certificate2(cert);
            Console.WriteLine($"Subject: {cert2.Subject}");
            Console.WriteLine($"Issuer: {cert2.Issuer}");
            Console.WriteLine($"Serial Number: {cert2.SerialNumber}");
            Console.WriteLine($"Thumbprint: {cert2.Thumbprint}");
            Console.WriteLine($"Valid From: {cert2.NotBefore}");
            Console.WriteLine($"Valid To: {cert2.NotAfter}");
        }
    }
}
