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

        static void Main(string[] args)
        {
            // Init output file
            File.WriteAllText(outputFile, $"Container Name, File Name, Public Key{Environment.NewLine}");

            // Get keyfiles for existing certs
            FindCertificateKeyFiles2();
            FindCertificateKeyFiles();

            // Find duplicate key files
            FindDuplicateKeyFiles();

            // We could capture the duplicates for a count, etc, but with 80GB of 3KB files -- I don't want to make a Dictionary/List that large
            // Use the output file to delete the dupes or delete them while going via File.Delete() etc
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

            while (CryptoAPI.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags2))
            {
                dwFlags2 = 0;

                var containerName = pbData.ToString();
                var publicKey = GetPublicKey(containerName);

                if (!String.IsNullOrEmpty(publicKey))
                {
                    if (publicKeys.Contains(publicKey))
                    {
                        // Dupe key, log to dupe list
                        var keyFile = GetUniqueContainerName(containerName);
                        if (!certKeyFiles.Contains(keyFile))
                        {
                            File.AppendAllText(outputFile, $"{containerName}, {GetUniqueContainerName(containerName)}, {publicKey}{Environment.NewLine}");

                            if (DELETE_DUPES)
                            {
                                var fileToDelete = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Crypto\RSA\MachineKeys", GetUniqueContainerName(containerName));
                                //File.Delete(fileToDelete);
                            }
                        }
                    }
                    else
                    {
                        publicKeys.Add(publicKey);
                    }
                }
            }
            if (hProv != IntPtr.Zero)
            {
                CryptoAPI.CryptReleaseContext(hProv, 0);
            }
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

        static string GetPublicKey(string containername, bool verbose = false)
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
                                    if (verbose)
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
                                        if (verbose)
                                            Log($"\tPublic key:\r\n{Convert.ToBase64String(array)}");

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

        static void FindCertificateKeyFiles2()
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (var certificate in store.Certificates)
                {
                    // These console outputs are just for debugging purposes
                    //Log($"Subject: {certificate.Subject}");
                    //Log($"\tIssuer: {certificate.Issuer}");

                    if (!certificate.HasPrivateKey)
                    {
                        //Log("\tNo private key associated with the certificate.");
                        continue;
                    }

                    // Check if the private key is of type RSACryptoServiceProvider
                    if (certificate.PrivateKey is RSACryptoServiceProvider rsaCsp)
                    {
                        // Check the ProviderType
                        switch (rsaCsp.CspKeyContainerInfo.ProviderType)
                        {
                            case 1:
                                Log($"\tKey provider: CSP - PROV_RSA_FULL");
                                break;
                            case 12:
                                Log($"\tKey provider: CSP - PROV_RSA_AES");
                                break;
                            case 24:
                                Log($"\tKey provider: KSP - PROV_RSA_AES");
                                break;
                            default:
                                Log($"\tKey provider: Unknown provider type: {rsaCsp.CspKeyContainerInfo.ProviderType}");
                                break;
                        }
                    }
                    else if (certificate.PrivateKey is RSACng)
                    {
                        // Key provider: KSP

                        // If it's RSACng, it's using KSP, and not in the MachineKeys folder (normally)
                        // We're still going to protect the file by adding it to the protected cert keyfiles list
                        var keyFile = ((RSACng)certificate.PrivateKey).Key.UniqueName;

                        if (!string.IsNullOrEmpty(keyFile))
                        {
                            // Path is either explicit, or %PROGRAMDATA%\Microsoft\Crypto\Keys\
                            certKeyFiles.Add(keyFile.Substring(keyFile.LastIndexOf('\\') + 1));
                        }
                    }

                    uint dataSize = 0;
                    if (!CryptoAPI.CertGetCertificateContextProperty(certificate.Handle, CryptoAPI.CERT_KEY_PROV_INFO_PROP_ID, IntPtr.Zero, ref dataSize))
                    {
                        Log(Marshal.GetLastWin32Error());
                    }

                    IntPtr dataBuffer = Marshal.AllocHGlobal((int)dataSize);
                    if (!CryptoAPI.CertGetCertificateContextProperty(certificate.Handle, CryptoAPI.CERT_KEY_PROV_INFO_PROP_ID, dataBuffer, ref dataSize))
                    {
                        Log(Marshal.GetLastWin32Error());
                    }

                    CRYPT_KEY_PROV_INFO provInfo = (CRYPT_KEY_PROV_INFO)Marshal.PtrToStructure(dataBuffer, typeof(CRYPT_KEY_PROV_INFO));
                    string containerName = provInfo.pwszContainerName;

                    Log($"\tKey Container Name: {containerName}");
                    Log($"\tFilename: {GetUniqueContainerName(containerName)}");

                    Marshal.FreeHGlobal(dataBuffer);
                }
            }
        }

        static Hashtable FindCertificateKeyFiles()
        {
            IntPtr zero = IntPtr.Zero;
            IntPtr intPtr = IntPtr.Zero;
            IntPtr intPtr2 = IntPtr.Zero;
            uint pcbData = 0u;
            Hashtable hashtable = new Hashtable();
            X509Certificate2 x509Certificate = null;
            uint dwFlags = CryptoAPI.CERT_SYSTEM_STORE_LOCAL_MACHINE | 0x8000u | 0x4000u;
            zero = CryptoAPI.CertOpenStore(CryptoAPI.CERT_STORE_PROV_SYSTEM, CryptoAPI.X509_ASN_ENCODING | CryptoAPI.PKCS_7_ASN_ENCODING, IntPtr.Zero, dwFlags, "MY");
            if (zero == IntPtr.Zero)
            {
                Log("Couldn't get certificate store handle");
                return hashtable;
            }

            while ((intPtr = CryptoAPI.CertEnumCertificatesInStore(zero, intPtr)) != IntPtr.Zero)
            {
                if (CryptoAPI.CertGetCertificateContextProperty(intPtr, 2, IntPtr.Zero, ref pcbData))
                {
                    intPtr2 = Marshal.AllocHGlobal((int)pcbData);
                    if (CryptoAPI.CertGetCertificateContextProperty(intPtr, 2, intPtr2, ref pcbData))
                    {
                        CRYPT_KEY_PROV_INFO cRYPT_KEY_PROV_INFO = (CRYPT_KEY_PROV_INFO)Marshal.PtrToStructure(intPtr2, typeof(CRYPT_KEY_PROV_INFO));

                        var keyFile = GetUniqueContainerName(cRYPT_KEY_PROV_INFO.pwszContainerName);

                        Log($"Protecting key file: {keyFile}");
                        certKeyFiles.Add(keyFile);

                        x509Certificate = new X509Certificate2(intPtr);
                        CERTPROPS_INFO value = new CERTPROPS_INFO(x509Certificate.GetCertHash(), x509Certificate.Subject);

                        //Console.Write("Public Key: ");

                        var publicKey = Convert.ToBase64String(x509Certificate.GetPublicKey());

                        if (publicKeys.Contains(publicKey))
                        {
                            Log("Duplicate, skipping");
                        }
                        else
                        {
                            publicKeys.Add(publicKey);
                        }
                    }
                }
                else
                {
                    Log(Marshal.GetLastWin32Error());
                }
            }
            if (intPtr2 != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(intPtr2);
            }
            if (intPtr != IntPtr.Zero)
            {
                CryptoAPI.CertFreeCertificateContext(intPtr);
            }
            if (zero != IntPtr.Zero)
            {
                CryptoAPI.CertCloseStore(zero, 0u);
            }
            return hashtable;
        }
    }
}
