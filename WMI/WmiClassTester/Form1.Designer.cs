namespace WmiClassTester
{
    partial class MainForm
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            txtWmiClass = new TextBox();
            label1 = new Label();
            btnQuery = new Button();
            dataGridViewResults = new DataGridView();
            labelError = new Label();
            label2 = new Label();
            txtWmiScope = new TextBox();
            comboTemplates = new ComboBox();
            label3 = new Label();
            ((System.ComponentModel.ISupportInitialize)dataGridViewResults).BeginInit();
            SuspendLayout();
            // 
            // txtWmiClass
            // 
            txtWmiClass.Location = new Point(77, 21);
            txtWmiClass.Name = "txtWmiClass";
            txtWmiClass.Size = new Size(198, 23);
            txtWmiClass.TabIndex = 0;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(6, 24);
            label1.Name = "label1";
            label1.Size = new Size(65, 15);
            label1.TabIndex = 1;
            label1.Text = "WMI Class:";
            // 
            // btnQuery
            // 
            btnQuery.Location = new Point(281, 20);
            btnQuery.Name = "btnQuery";
            btnQuery.Size = new Size(75, 23);
            btnQuery.TabIndex = 2;
            btnQuery.Text = "Query";
            btnQuery.UseVisualStyleBackColor = true;
            btnQuery.Click += btnQuery_Click;
            // 
            // dataGridViewResults
            // 
            dataGridViewResults.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            dataGridViewResults.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            dataGridViewResults.Location = new Point(12, 85);
            dataGridViewResults.Name = "dataGridViewResults";
            dataGridViewResults.Size = new Size(765, 403);
            dataGridViewResults.TabIndex = 3;
            // 
            // labelError
            // 
            labelError.AutoSize = true;
            labelError.Location = new Point(362, 24);
            labelError.Name = "labelError";
            labelError.Size = new Size(0, 15);
            labelError.TabIndex = 4;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(29, 59);
            label2.Name = "label2";
            label2.Size = new Size(42, 15);
            label2.TabIndex = 5;
            label2.Text = "Scope:";
            // 
            // txtWmiScope
            // 
            txtWmiScope.Location = new Point(77, 56);
            txtWmiScope.Name = "txtWmiScope";
            txtWmiScope.Size = new Size(279, 23);
            txtWmiScope.TabIndex = 6;
            txtWmiScope.Text = "\\\\.\\ROOT\\StandardCimv2";
            // 
            // comboTemplates
            // 
            comboTemplates.FormattingEnabled = true;
            comboTemplates.Location = new Point(552, 51);
            comboTemplates.Name = "comboTemplates";
            comboTemplates.Size = new Size(225, 23);
            comboTemplates.TabIndex = 7;
            comboTemplates.SelectedIndexChanged += comboTemplates_SelectedIndexChanged;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new Point(460, 54);
            label3.Name = "label3";
            label3.Size = new Size(86, 15);
            label3.TabIndex = 8;
            label3.Text = "Quick Settings:";
            // 
            // MainForm
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(789, 500);
            Controls.Add(label3);
            Controls.Add(comboTemplates);
            Controls.Add(txtWmiScope);
            Controls.Add(label2);
            Controls.Add(labelError);
            Controls.Add(dataGridViewResults);
            Controls.Add(btnQuery);
            Controls.Add(label1);
            Controls.Add(txtWmiClass);
            Name = "MainForm";
            Text = "WMI Class Tester";
            ((System.ComponentModel.ISupportInitialize)dataGridViewResults).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private TextBox txtWmiClass;
        private Label label1;
        private Button btnQuery;
        private DataGridView dataGridViewResults;
        private Label labelError;
        private Label label2;
        private TextBox txtWmiScope;
        private ComboBox comboTemplates;
        private Label label3;
    }
}
