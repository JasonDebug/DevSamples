using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace KeyTool.net
{
    internal class CryptoAPI
    {
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CertOpenStore(
            uint storeProvider,
            uint encodingType,
            IntPtr hCryptProv,
            uint flags,
            string pvPara);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertCloseStore(
            IntPtr hCertStore,
            uint dwFlags);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertGetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertFindCertificateInStore(
            IntPtr hCertStore,
            uint dwCertEncodingType,
            uint dwFindFlags,
            uint dwFindType,
            IntPtr pvFindPara,
            IntPtr pPrevCertContext);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetProvParam(IntPtr hProv,
                                                    uint dwParam,
                                                    [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData,
                                                    ref uint dwDataLen,
                                                    uint dwFlags);

        [DllImport("advapi32.dll")]
        public static extern bool CryptGetUserKey(IntPtr hProv, uint dwKeySpec, ref IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptExportKey(IntPtr hKey, IntPtr hExpKey, uint dwBlobType, uint dwFlags, [In][Out] byte[] pbData, ref uint dwDataLen);

        [DllImport("advapi32.dll")]
        public static extern bool CryptDestroyKey(IntPtr hKey);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        [DllImport("advapi32", SetLastError = true)]
        internal extern static bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertFreeCertificateContext(IntPtr hCertStore);

        internal const int PROV_RSA_FULL = 1;
        internal const int X509_ASN_ENCODING = 0x00000001;
        internal const int PKCS_7_ASN_ENCODING = 0x10000;
        internal const uint CRYPT_FIRST = 1;
        internal const uint CRYPT_NEXT = 2;

        internal const uint CSPKEYTYPE = 32;
        internal const int CERT_KEY_PROV_INFO_PROP_ID = 2;

        #region CryptGetProvParamType
        internal const uint PP_ENUMALGS = 1;
        internal const uint PP_ENUMCONTAINERS = 2;
        internal const uint PP_IMPTYPE = 3;
        internal const uint PP_NAME = 4;
        internal const uint PP_VERSION = 5;
        internal const uint PP_CONTAINER = 6;
        internal const uint PP_CHANGE_PASSWORD = 7;
        internal const uint PP_KEYSET_SEC_DESCR = 8;       // get/set security descriptor of keyset
        internal const uint PP_CERTCHAIN = 9;      // for retrieving certificates from tokens
        internal const uint PP_KEY_TYPE_SUBTYPE = 10;
        internal const uint PP_PROVTYPE = 16;
        internal const uint PP_KEYSTORAGE = 17;
        internal const uint PP_APPLI_CERT = 18;
        internal const uint PP_SYM_KEYSIZE = 19;
        internal const uint PP_SESSION_KEYSIZE = 20;
        internal const uint PP_UI_PROMPT = 21;
        internal const uint PP_ENUMALGS_EX = 22;
        internal const uint PP_ENUMMANDROOTS = 25;
        internal const uint PP_ENUMELECTROOTS = 26;
        internal const uint PP_KEYSET_TYPE = 27;
        internal const uint PP_ADMIN_PIN = 31;
        internal const uint PP_KEYEXCHANGE_PIN = 32;
        internal const uint PP_SIGNATURE_PIN = 33;
        internal const uint PP_SIG_KEYSIZE_INC = 34;
        internal const uint PP_KEYX_KEYSIZE_INC = 35;
        internal const uint PP_UNIQUE_CONTAINER = 36;
        internal const uint PP_SGC_INFO = 37;
        internal const uint PP_USE_HARDWARE_RNG = 38;
        internal const uint PP_KEYSPEC = 39;
        internal const uint PP_ENUMEX_SIGNING_PROT = 40;
        internal const uint PP_CRYPT_COUNT_KEY_USE = 41;
        #endregion

        #region CryptAcquireContextFlags
        internal const uint CRYPT_NONE = 0x00000000;
        internal const uint CRYPT_NEWKEYSET = 0x00000008;         // CRYPT_NEWKEYSET
        internal const uint CRYPT_DELETEKEYSET = 0x00000010;      // CRYPT_DELETEKEYSET
        internal const uint CRYPT_MACHINE_KEYSET = 0x00000020;    // CRYPT_MACHINE_KEYSET
        internal const uint CRYPT_SILENT = 0x00000040;            // CRYPT_SILENT
        internal const uint CRYPT_VERIFYCONTEXT = 0xF0000000;      // CRYPT_VERIFYCONTEXT
        #endregion

        #region CertOpenStoreProvider
        internal const uint CERT_STORE_PROV_MEMORY = 2;
        internal const uint CERT_STORE_PROV_SYSTEM = 10;
        internal const uint CERT_STORE_PROV_SYSTEM_REGISTRY = 13;
        #endregion

        #region CertOpenStoreFlags
        internal const uint CERT_STORE_NO_CRYPT_RELEASE_FLAG = 0x00000001;
        internal const uint CERT_STORE_SET_LOCALIZED_NAME_FLAG = 0x00000002;
        internal const uint CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG = 0x00000004;
        internal const uint CERT_STORE_DELETE_FLAG = 0x00000010;
        internal const uint CERT_STORE_UNSAFE_PHYSICAL_FLAG = 0x00000020;
        internal const uint CERT_STORE_SHARE_STORE_FLAG = 0x00000040;
        internal const uint CERT_STORE_SHARE_CONTEXT_FLAG = 0x00000080;
        internal const uint CERT_STORE_MANIFOLD_FLAG = 0x00000100;
        internal const uint CERT_STORE_ENUM_ARCHIVED_FLAG = 0x00000200;
        internal const uint CERT_STORE_UPDATE_KEYID_FLAG = 0x00000400;
        internal const uint CERT_STORE_BACKUP_RESTORE_FLAG = 0x00000800;
        internal const uint CERT_STORE_READONLY_FLAG = 0x00008000;
        internal const uint CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
        internal const uint CERT_STORE_CREATE_NEW_FLAG = 0x00002000;
        internal const uint CERT_STORE_MAXIMUM_ALLOWED_FLAG = 0x00001000;

        internal const uint CERT_SYSTEM_STORE_CURRENT_USER = 1 << 16;
        internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE = 2 << 16;
        internal const uint CERT_SYSTEM_STORE_CURRENT_SERVICE = 4 << 16;
        internal const uint CERT_SYSTEM_STORE_SERVICES = 5 << 16;
        internal const uint CERT_SYSTEM_STORE_USERS = 6 << 16;
        internal const uint CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY = 7 << 16;
        internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY = 8 << 16;
        internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = 9 << 16;
        #endregion
    }

    public struct CRYPT_KEY_PROV_INFO
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszContainerName;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszProvName;

        public uint dwProvType;

        public uint dwFlags;

        public uint cProvParam;

        public IntPtr rgProvParam;

        public uint dwKeySpec;
    }

    public sealed class CERTPROPS_INFO
    {
        private byte[] sha1hash;

        private string SubjectNameCN;

        public byte[] Hash => sha1hash;

        public string Name => SubjectNameCN;

        public CERTPROPS_INFO(byte[] hash, string certsubjname)
        {
            sha1hash = hash;
            SubjectNameCN = certsubjname;
        }
    }
}
