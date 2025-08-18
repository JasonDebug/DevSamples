using System.Management;

namespace WmiClassTester
{
    public partial class MainForm : Form
    {
        private static string wmiScope = @"\\.\ROOT\Cimv2";
        private static string wmiStandardScope = @"\\.\ROOT\StandardCimv2";

        private Dictionary<string, WmiInfo> wmiMappings;

        public MainForm()
        {
            InitializeComponent();
            PopulateControls();
        }

        private void PopulateControls()
        {
            wmiMappings = new Dictionary<string, WmiInfo>
            {
                { "Global Settings", new WmiInfo("MSFT_NetSecuritySettingData", wmiStandardScope) },
                { "Firewall Profiles", new WmiInfo("MSFT_NetFirewallProfile", wmiStandardScope) },
                { "Firewall Rules", new WmiInfo("MSFT_NetFirewallRule", wmiStandardScope) },
                { "Network Adapters", new WmiInfo("Win32_NetworkAdapter", wmiScope) }
            };

            foreach (var item in wmiMappings.Keys)
            {
                comboTemplates.Items.Add(item);
            }

            comboTemplates.SelectedIndex = -1; // Ensure no item is selected initially
        }

        private void btnQuery_Click(object sender, EventArgs e)
        {
            string wmiClass = txtWmiClass.Text.Trim();

            if (string.IsNullOrEmpty(wmiClass))
            {
                MessageBox.Show("Please enter a WMI class name.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                // Clear existing results
                dataGridViewResults.Rows.Clear();
                dataGridViewResults.Columns.Clear();

                // Connect to WMI namespace
                ManagementScope scope = new ManagementScope(txtWmiScope.Text.Trim());
                scope.Connect();

                // Query the WMI class
                string query = $"SELECT * FROM {wmiClass}";
                ObjectQuery objectQuery = new ObjectQuery(query);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, objectQuery);
                ManagementObjectCollection results = searcher.Get();

                // Dynamically create columns based on the properties of the first instance
                bool columnsCreated = false;

                foreach (ManagementObject obj in results)
                {
                    if (!columnsCreated)
                    {
                        foreach (PropertyData property in obj.Properties)
                        {
                            dataGridViewResults.Columns.Add(property.Name, property.Name);
                        }
                        columnsCreated = true;
                    }

                    // Add a new row for each instance
                    DataGridViewRow row = new DataGridViewRow();
                    row.CreateCells(dataGridViewResults);

                    int columnIndex = 0;
                    foreach (PropertyData property in obj.Properties)
                    {
                        object value = property.Value;
                        row.Cells[columnIndex].Value = value ?? "NULL";
                        columnIndex++;
                    }

                    dataGridViewResults.Rows.Add(row);
                }

                if (!columnsCreated)
                {
                    labelError.Text = "No properties found for the specified WMI class.";
                }
                else
                {
                    labelError.Text = string.Empty;
                }
            }
            catch (Exception ex)
            {
                //MessageBox.Show($"Error querying WMI class: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelError.Text = $"Error querying WMI class: {ex.Message}";
            }
        }

        private void comboTemplates_SelectedIndexChanged(object sender, EventArgs e)
        {
            string selectedItem = comboTemplates.SelectedItem?.ToString();

            if (!string.IsNullOrEmpty(selectedItem) && wmiMappings.TryGetValue(selectedItem, out WmiInfo wmiInfo))
            {
                txtWmiClass.Text = wmiInfo.WmiClass;
                txtWmiScope.Text = wmiInfo.WmiScope;
            }
        }

        private struct WmiInfo
        {
            public string WmiClass { get; set; }
            public string WmiScope { get; set; }

            public WmiInfo(string wmiClass, string wmiScope)
            {
                WmiClass = wmiClass;
                WmiScope = wmiScope;
            }
        }
    }
}
