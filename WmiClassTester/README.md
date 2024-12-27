#### WmiClassTester

A simple WinForms (C#) app to dump WMI class output to a DataGrid. There are prepopulated classes but ultimately this is the same as running something like

```PowerShell
Get-CimInstance MSFT_NetSecuritySettingData -Namespace ROOT\StandardCimv2
```
