using MS.Internal.IO.Packaging;
using System;
using System.Text;

namespace IsolatedStorageFix
{
    public partial class _Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            try
            {
                // Get the SIDs for the affected application pools
                var IsolatedStorageTestPoolSid = GetApplicationPoolSid("IsolatedStorageTestPool");
                var IsolatedStorageTest2 = GetApplicationPoolSid("IsolatedStorageTest2");

                // Update the process token DACL to include the application pool SID for all required applications that share IsolatedStorage
                ProcessTokenDaclUpdater updater = new ProcessTokenDaclUpdater();
                updater.AddSidToProcessTokenDacl(IsolatedStorageTestPoolSid);
                updater.AddSidToProcessTokenDacl(IsolatedStorageTest2);

                // Dump the process token DACL to the page
                ProcessTokenDaclDumper procDumper = new ProcessTokenDaclDumper();
                Response.Write(procDumper.OutputProcessTokenDacl());

                string _filename = null;
                LogToPage(Environment.NewLine);
                LogToPage("CreateUserScopedIsolatedStorageFileStreamWithRandomName");

                // For illustrative purposes, do not dispose the stream so the mutex survives until GC
                PackagingUtilities.CreateUserScopedIsolatedStorageFileStreamWithRandomName(3, out _filename);
                LogToPage("Successfully created mutex.");
            }
            catch (Exception ex)
            {
                LogToPage($"An error occurred: {ex.ToString().Replace(Environment.NewLine, "<br/>")}<br/>");
            }
        }

        // The application pool SID is just a hash of the name with a well-known prefix
        private static string GetApplicationPoolSid(string appPoolName)
        {
            var calculatedSid = "S-1-5-82";
            appPoolName = appPoolName.ToLower();

            var hashBytes = Encoding.Unicode.GetBytes(appPoolName);
            var sha1 = new System.Security.Cryptography.SHA1CryptoServiceProvider();
            var hash = sha1.ComputeHash(hashBytes);

            for (int i = 0; i < 5; i++)
            {
                calculatedSid += "-" + BitConverter.ToUInt32(hash, i*4);
            }

            return calculatedSid;
        }

        private void LogToPage(string message)
        {
            Response.Write($"{message}<br/>");
        }
    }
}
