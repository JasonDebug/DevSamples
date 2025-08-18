using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;

namespace CheckComboBoxTest {
    public partial class Form1 : Form {
        private string[] coloursArr = { "Red", "Green", "Black", "White", "Orange", "Yellow", "Blue", "Maroon", "Pink", "Purple" };
        // ,"A very long string exceeding the dropdown width and forcing a scrollbar to appear to make the content viewable"};

        public Form1() {
            InitializeComponent();
            // Manually add handler for when an item check state has been modified.
            ccb.ItemCheck += new System.Windows.Forms.ItemCheckEventHandler(this.ccb_ItemCheck);
        }

        private void Form1_Load(object sender, EventArgs e) {
            for (int i = 0; i < coloursArr.Length; i++) {
                CCBoxItem item = new CCBoxItem(coloursArr[i], i);
                ccb.Items.Add(item);
            }
            // If more then 5 items, add a scroll bar to the dropdown.
            ccb.MaxDropDownItems = 5;
            // Make the "Name" property the one to display, rather than the ToString() representation.
            ccb.DisplayMember = "Name";
            ccb.ValueSeparator = ", ";
            // Check the first 2 items.
            ccb.SetItemChecked(0, true);
            ccb.SetItemChecked(1, true);
            //ccb.SetItemCheckState(1, CheckState.Indeterminate);
        }

        private void ccb_DropDownClosed(object sender, EventArgs e) {
            txtOut.AppendText("DropdownClosed\r\n");
            txtOut.AppendText(string.Format("value changed: {0}\r\n", ccb.ValueChanged));
            txtOut.AppendText(string.Format("value: {0}\r\n", ccb.Text));
            // Display all checked items.
            StringBuilder sb = new StringBuilder("Items checked: ");
            foreach (CCBoxItem item in ccb.CheckedItems) {
                sb.Append(item.Name).Append(ccb.ValueSeparator);
            }
            sb.Remove(sb.Length-ccb.ValueSeparator.Length, ccb.ValueSeparator.Length);
            txtOut.AppendText(sb.ToString());
            txtOut.AppendText("\r\n");
        }

        private void ccb_ItemCheck(object sender, ItemCheckEventArgs e) {
            CCBoxItem item = ccb.Items[e.Index] as CCBoxItem;
            txtOut.AppendText(string.Format("Item '{0}' is being set to {1}\r\n", item.Name, e.NewValue.ToString()));
        }        
    }
}