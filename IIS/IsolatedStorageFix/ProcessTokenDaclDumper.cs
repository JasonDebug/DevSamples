namespace IsolatedStorageFix
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.AccessControl;
    using System.Text;

    public class ProcessTokenDaclDumper
    {
        // P/Invoke for OpenProcessToken
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        // P/Invoke for GetTokenInformation
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        // P/Invoke for CloseHandle
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private void Log(StringBuilder sb, string message)
        {
            sb.AppendLine($"{message}<br/>");
        }

        // Constants for token access and information
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenDefaultDacl = 6;
        private IntPtr tokenInfo = IntPtr.Zero;

        public string OutputProcessTokenDacl()
        {
            var sb = new StringBuilder();

            // Open the process token
            IntPtr processHandle = System.Diagnostics.Process.GetCurrentProcess().Handle;
            if (!OpenProcessToken(processHandle, TOKEN_QUERY, out IntPtr tokenHandle))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to open process token");
            }

            try
            {
                // Retrieve the current DACL
                uint tokenInfoLength = 0;
                GetTokenInformation(tokenHandle, TokenDefaultDacl, IntPtr.Zero, 0, out tokenInfoLength);
                tokenInfo = Marshal.AllocHGlobal((int)tokenInfoLength);

                if (!GetTokenInformation(tokenHandle, TokenDefaultDacl, tokenInfo, tokenInfoLength, out _))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to get token information");
                }

                // Get the current DACL from the token information
                TOKEN_DEFAULT_DACL tokenDefaultDacl = Marshal.PtrToStructure<TOKEN_DEFAULT_DACL>(tokenInfo);
                IntPtr pAcl = tokenDefaultDacl.DefaultDacl;

                if (pAcl == IntPtr.Zero)
                {
                    Log(sb, "No DACL found.");
                    return sb.ToString();
                }

                // Read the ACL into a byte array
                //int aclSize = Marshal.ReadInt32(pAcl, 4);
                int aclSize = 4096;
                byte[] aclBuffer = new byte[aclSize];
                Marshal.Copy(pAcl, aclBuffer, 0, aclSize);

                // Convert the byte array to a RawAcl
                RawAcl rawAcl = new RawAcl(aclBuffer, 0);

                // Output the DACL entries
                Log(sb, "Process token's default DACL:");
                foreach (CommonAce ace in rawAcl)
                {
                    Log(sb, $"- Identity: {ace.SecurityIdentifier}");
                    Log(sb, $"--- Access Type: {ace.AceType}");
                    Log(sb, $"--- Access Mask: {ace.AccessMask}");
                    Log(sb, $"--- Inheritance Flags: {ace.InheritanceFlags}");
                    Log(sb, $"--- Propagation Flags: {ace.PropagationFlags}");
                }
            }
            finally
            {
                // Clean up
                Marshal.FreeHGlobal(tokenInfo);
                CloseHandle(tokenHandle);
            }

            return sb.ToString();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_DEFAULT_DACL
        {
            public IntPtr DefaultDacl;
        }
    }
}
