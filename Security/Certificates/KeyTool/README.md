# Find Orphaned/Duplicate Keys - KeyTool

This is mostly native Win32 code, invoked from C#.  This is what the sample shows:
-	Scan certificates in Local Machine\Personal store and save public keys and file paths for protection
-	Scan all Local Machine\Personal keys, and log all duplicates to a CSV, minus the ones saved in the last step
-	Scan all physical files in the MachineKeys folder and compare with the protected key files

Note that this is just a sample, and not meant to be run in production, sold, etc.  This is not designed to be fully robust, memory efficient, or bug free.  It illustrates various APIs required to get at the key stores we can’t get to with .NET.  It simply illustrates how a tool could be written to do what you need – clear up the duplicate and orphaned files in your MachineKeys folder.  Test all code in a test environment.
