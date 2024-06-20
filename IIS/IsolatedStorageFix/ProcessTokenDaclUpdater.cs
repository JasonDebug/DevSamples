namespace IsolatedStorageFix
{
    using System;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security.AccessControl;
    using System.Security.Principal;

    public class ProcessTokenDaclUpdater
    {
        // P/Invoke for OpenProcessToken
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        // P/Invoke for GetTokenInformation
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        // P/Invoke for SetTokenInformation
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength);

        // P/Invoke for CloseHandle
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        // Constants for token access and information
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenDefaultDacl = 6;

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_DEFAULT_DACL
        {
            public IntPtr DefaultDacl;
        }

        [Flags]
        private enum GenericAccessRights
        {
            GENERIC_ALL = 0x10000000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ACL_SIZE_INFORMATION
        {
            public uint AceCount;
            public uint AclBytesInUse;
            public uint AclBytesFree;
        }

        // P/Invoke signature for GetAclInformation
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetAclInformation(
            IntPtr pAcl,
            out ACL_SIZE_INFORMATION pAclInformation,
            uint nAclInformationLength,
            ACL_INFORMATION_CLASS dwAclInformationClass
        );

        public enum ACL_INFORMATION_CLASS
        {
            AclRevisionInformation = 1,
            AclSizeInformation = 2
        }

        public void AddSidToProcessTokenDacl(string newSid)
        {
            // Open the process token so we can retrieve the DACL and modify it
            // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
            // https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
            IntPtr processHandle = System.Diagnostics.Process.GetCurrentProcess().Handle;
            if (!OpenProcessToken(processHandle, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, out IntPtr tokenHandle))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to open process token");
            }

            IntPtr tokenInfo = IntPtr.Zero;
            IntPtr newAcl = IntPtr.Zero;

            try
            {
                // Retrieve the current DACL
                // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
                
                // Get the token length
                uint tokenInfoLength = 0;
                GetTokenInformation(tokenHandle, TokenDefaultDacl, IntPtr.Zero, 0, out tokenInfoLength);
                
                // Get the token
                tokenInfo = Marshal.AllocHGlobal((int)tokenInfoLength);
                if (!GetTokenInformation(tokenHandle, TokenDefaultDacl, tokenInfo, tokenInfoLength, out _))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to get token information");
                }

                // Get the current DACL from the token
                TOKEN_DEFAULT_DACL tokenDefaultDacl = Marshal.PtrToStructure<TOKEN_DEFAULT_DACL>(tokenInfo);
                IntPtr pAcl = tokenDefaultDacl.DefaultDacl;
                if (pAcl == IntPtr.Zero)
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "No DACL found.");
                }

                // Get the size of the ACL
                ACL_SIZE_INFORMATION aclSizeInfo;
                int aclSizeInfoSize = Marshal.SizeOf(typeof(ACL_SIZE_INFORMATION));
                if (!GetAclInformation(pAcl, out aclSizeInfo, (uint)aclSizeInfoSize, ACL_INFORMATION_CLASS.AclSizeInformation))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to get ACL size information.");
                }

                // Use the actual size of the ACL
                uint aclSize = aclSizeInfo.AclBytesInUse + 16;
                byte[] aclBuffer = new byte[aclSize];
                Marshal.Copy(pAcl, aclBuffer, 0, (int)aclSize);

                // Convert the byte array to a RawAcl
                RawAcl rawAcl = new RawAcl(aclBuffer, 0);

                foreach (CommonAce ace in rawAcl.Cast<CommonAce>())
                {
                    if (ace.SecurityIdentifier.Value == newSid)
                    {
                        // The SID is already in the DACL
                        return;
                    }
                }

                // Create a new rule for the additional application pool SID
                SecurityIdentifier additionalSid = new SecurityIdentifier(newSid);
                CommonAce newAce = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, (int)GenericAccessRights.GENERIC_ALL, additionalSid, false, null);

                // Add the new rule to the ACL
                rawAcl.InsertAce(rawAcl.Count, newAce);

                // Convert the RawAcl back to a binary form
                byte[] binaryForm = new byte[rawAcl.BinaryLength];
                rawAcl.GetBinaryForm(binaryForm, 0);
                newAcl = Marshal.AllocHGlobal(binaryForm.Length);
                Marshal.Copy(binaryForm, 0, newAcl, binaryForm.Length);

                // Update the token's default DACL
                tokenDefaultDacl.DefaultDacl = newAcl;
                Marshal.StructureToPtr(tokenDefaultDacl, tokenInfo, false);

                // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-settokeninformation
                if (!SetTokenInformation(tokenHandle, TokenDefaultDacl, tokenInfo, tokenInfoLength))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to set token information");
                }
            }
            finally
            {
                // Clean up
                if (tokenInfo != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(tokenInfo);
                }
                if (newAcl != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(newAcl);
                }
                CloseHandle(tokenHandle);
            }
        }
    }
}
