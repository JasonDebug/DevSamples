using System.Collections;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KeyTool.net
{
    internal class Program
    {
        const bool DELETE_DUPES = false;
        const bool VERBOSE = false;

        static List<string> certKeyFiles = new List<string>();
        static List<string> publicKeys = new List<string>();
        static string outputFile = "duplicateFiles.csv";
        static string[] providers = new string[]
        {
                "Microsoft Base Cryptographic Provider v1.0",
                "Microsoft Strong Cryptographic Provider",
                "Microsoft Enhanced Cryptographic Provider v1.0",
                "Microsoft Enhanced RSA and AES Cryptographic Provider"
        };
        static string MachineKeysFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Crypto\RSA\MachineKeys");

        static void Main(string[] args)
        {
            // Init output file
            File.WriteAllText(outputFile, $"Container Name, File Name, Public Key{Environment.NewLine}");

            // Get keyfiles and public keys for existing certs
            FindCertificateKeyFiles();

            // Find duplicate key files
            FindDuplicateKeyFiles();

            // Compare with physical key files.  Any files in here that we can't see from APIs is probably orphaned
            FindOrphanedKeyFiles();
        }

        static void Log(string message)
        {
            Console.WriteLine(message);
        }

        static void Log(int number)
        {
            Log(number.ToString());
        }

        private static void FindDuplicateKeyFiles()
        {
            uint dwDataLen = 0;
            string pszProvider = null;
            string pszContainer = null;
            uint dwProvType = 1;
            uint dwFlags = 0xF0000000 | 0x20;
            uint dwFlags2 = 1;
            uint dwParam = 2;
            IntPtr hProv = IntPtr.Zero;
            
            if (!CryptoAPI.CryptAcquireContext(ref hProv, pszContainer, pszProvider, dwProvType, dwFlags))
            {
                Log(Marshal.GetLastWin32Error());
                return;
            }

            StringBuilder pbData = null;
            CryptoAPI.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags2);

            int num = (int)(2 * dwDataLen);
            pbData = new StringBuilder(num);
            dwFlags2 = 1;
            uint index = 0;
            uint dupes = 0;

            while (CryptoAPI.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags2))
            {
                index++;
                dwFlags2 = 0;

                var containerName = pbData.ToString();
                var keyFile = GetUniqueContainerName(containerName);
                var publicKey = GetPublicKey(containerName);

                if (!String.IsNullOrEmpty(publicKey))
                {
                    if (publicKeys.Contains(publicKey))
                    {
                        // Dupe key, log to dupe list
                        if (!certKeyFiles.Contains(keyFile))
                        {
                            // We could capture the duplicates for a count, etc, but with 80GB of 3KB files -- we don't want to make a Dictionary/List
                            // Instead, we'd do this realtime and delete the dupes as we go or delete them after the fact via an external file
                            // DELETE_DUPES is false, so we don't delete anything, but we could by setting that to true

                            File.AppendAllText(outputFile, $"{containerName}, {keyFile}, {publicKey}{Environment.NewLine}");
                            dupes++;

                            if (DELETE_DUPES)
                            {
                                var fileToDelete = Path.Combine(MachineKeysFilePath, keyFile);

                                // Delete the file !!
                                //File.Delete(fileToDelete);
                            }
                        }
                    }
                    else
                    {
                        // Add the file to the list for the last step in cleanup
                        certKeyFiles.Add(keyFile);

                        publicKeys.Add(publicKey);
                    }
                }
            }
            if (hProv != IntPtr.Zero)
            {
                CryptoAPI.CryptReleaseContext(hProv, 0);
            }

            Log($"Found {index} keys -- {dupes} duplicates.");
        }

        static string GetUniqueContainerName(string containername)
        {
            uint dwDataLen = 256;
            uint dwFlags = 0;
            uint dwProvType = CryptoAPI.PROV_RSA_FULL;
            uint dwParam = CryptoAPI.PP_UNIQUE_CONTAINER;
            IntPtr hProv = IntPtr.Zero;

            try
            {
                foreach (string provider in providers)
                {
                    if (CryptoAPI.CryptAcquireContext(ref hProv, containername, provider, dwProvType, CryptoAPI.CSPKEYTYPE))
                    {
                        StringBuilder stringBuilder = new StringBuilder(256);
                        if (CryptoAPI.CryptGetProvParam(hProv, dwParam, stringBuilder, ref dwDataLen, dwFlags))
                        {
                            return stringBuilder.ToString();
                        }
                    }
                }
            }
            finally
            {
                if (hProv != IntPtr.Zero)
                {
                    CryptoAPI.CryptReleaseContext(hProv, 0);
                }
            }

            return string.Empty;
        }

        static string GetPublicKey(string containername)
        {
            uint dwProvType = CryptoAPI.PROV_RSA_FULL;
            uint dwBlobType = 6;    // PUBLICKEYBLOB
            uint dwDataLen = 0;
            IntPtr hProv = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            IntPtr zero = IntPtr.Zero;

            try
            {
                foreach (string provider in providers)
                {
                    if (CryptoAPI.CryptAcquireContext(ref hProv, containername, provider, dwProvType, CryptoAPI.CSPKEYTYPE))
                    {
                        // Keys can technically have both a signature and an exchange key, but we'll return the exchange key (1) if it exists
                        for (uint keySpec = 1; keySpec <= 2; keySpec++)
                        {
                            if (CryptoAPI.CryptGetUserKey(hProv, keySpec /* Exchange / Signature key */, ref hKey))
                            {
                                if (!CryptoAPI.CryptExportKey(hKey, zero, dwBlobType, 0, null, ref dwDataLen))
                                {
                                    Log(Marshal.GetLastWin32Error());

                                    return string.Empty;
                                }
                                else
                                {
                                    byte[] array = new byte[dwDataLen];
                                    if (!CryptoAPI.CryptExportKey(hKey, zero, dwBlobType, 0, array, ref dwDataLen))
                                    {
                                        return string.Empty;
                                    }
                                    else
                                    {
                                        return Convert.ToBase64String(array);
                                    }
                                }
                            }
                        }
                    }
                }

                return string.Empty;
            }
            finally
            {
                if (IntPtr.Zero != hKey)
                    CryptoAPI.CryptDestroyKey(hKey);

                if (IntPtr.Zero != hProv)
                    CryptoAPI.CryptReleaseContext(hProv, 0);
            }
        }

        /// <summary>
        /// Populate the certKeyFiles list with all the cert key files
        /// </summary>
        static void FindCertificateKeyFiles()
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (var certificate in store.Certificates)
                {
                    // Protect via public key as well
                    publicKeys.Add(Convert.ToBase64String(certificate.GetPublicKey()));

                    if (!certificate.HasPrivateKey)
                        continue;

                    string keyFile = null;

                    if (certificate.PrivateKey is RSACng rsaCng)
                    {
                        // If it's RSACng, it's using KSP, and not in the MachineKeys folder (normally)
                        // We're still going to protect the file by adding it to the protected cert keyfiles list
                        keyFile = rsaCng.Key.UniqueName;
                    }
                    else if (certificate.PrivateKey is RSACryptoServiceProvider rsaCsp)
                    {
                        // This should work for CSPs but I cannot get a cert to import that way to test
                        keyFile = rsaCsp.CspKeyContainerInfo.UniqueKeyContainerName;
                    }

                    if (!string.IsNullOrEmpty(keyFile) && !certKeyFiles.Contains(keyFile))
                    {
                        // Path is generally either fully qualified, or %PROGRAMDATA%\Microsoft\Crypto\Keys\
                        certKeyFiles.Add(keyFile.Substring(keyFile.LastIndexOf('\\') + 1));
                    }
                }
            }
        }

        static void FindOrphanedKeyFiles()
        {
            uint index = 0;
            foreach (var file in Directory.GetFiles(MachineKeysFilePath))
            {
                var keyFile = Path.GetFileName(file);

                if (!certKeyFiles.Contains(keyFile))
                {
                    index++;

                    //File.Delete(file);
                }
            }
            Console.WriteLine($"Found {index} orphaned key files.");
        }
    }
}
