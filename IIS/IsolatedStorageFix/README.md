### IsolatedStorageFix Example

IsolatedStorage calls may fail when multiple separate application pools are running under the same service account with long-running operations.

#### Cause

The IsolatedStorage store is locked when in use, and Mutexes are used to manage this lock. Understanding the following points is crucial:

-   **Process DACL Modification**: When the application starts, it modifies the default DACL for the process to include SYSTEM, Administrators, OWNER, and itself (the current w3wp instance). This enhances security with a minimal and inclusive list.
-   **Mutex ACL**: The mutex used by IsolatedStorage is created with the same ACL as the default DACL for the process.
-   **User-Specific Store**: The IsolatedStorage store is unique per user. If the same service account runs multiple applications, the store will be shared across them. ApplicationPoolIdentity is effectively SYSTEM and is unaffected.
-   **Instance Sharing**: Multiple instances of an application running under the same application pool will run in the same w3wp.exe instance by default.
-   **Mutex Reuse**: A mutex will be reused if it is open, retaining its current ACL.

Taking all the above into account, when multiple application pools run with the same service account, IsolatedStorage can fail. This failure occurs because if those pools try to access the store simultaneously, the mutex will not contain the other application's SID, restricting access. This issue generally arises only during long-running operations in IsolatedStorage as the mutex is disposed of after the store use is completed.

#### Mitigation

There are multiple ways to mitigate the above issue:

-   **Same Application Pool**: Use the same application pool for applications that need to use the same service account.
-   **Different Service Accounts**: Use a different service account for each application pool.
-   **Modify Default DACL**: Modify the process token's Default DACL to include the SIDs for the other application pools that need access to the same service account's IsolatedStorage store. The following code demonstrates this solution.

**Examples**

When the second application launches while the first application's mutex is still alive, we can see the single SID ACE and get the exception 

> System.IO.IsolatedStorage.IsolatedStorageException: Unable to create mutex. (Exception from HRESULT: 0x80131464)

    Process token's default DACL:
    - Identity: S-1-5-18
    --- Access Type: AccessAllowed
    --- Access Mask: 268435456
    --- Inheritance Flags: None
    --- Propagation Flags: None
    - Identity: S-1-5-32-544
    --- Access Type: AccessAllowed
    --- Access Mask: 268435456
    --- Inheritance Flags: None
    --- Propagation Flags: None
    - Identity: S-1-3-4
    --- Access Type: AccessAllowed
    --- Access Mask: 131072
    --- Inheritance Flags: None
    --- Propagation Flags: None
    - Identity: S-1-5-82-2677836526-1559996366-876931565-3569012157-1367525312
    --- Access Type: AccessAllowed
    --- Access Mask: 268435456
    --- Inheritance Flags: None
    --- Propagation Flags: None
    
    CreateUserScopedIsolatedStorageFileStreamWithRandomName
    An error occurred: System.IO.IsolatedStorage.IsolatedStorageException: Unable to create mutex. (Exception from HRESULT: 0x80131464)
    at System.IO.IsolatedStorage.IsolatedStorageFile.Open(String infoFile, String syncName)
    at System.IO.IsolatedStorage.IsolatedStorageFile.Lock(Boolean& locked)
    at System.IO.IsolatedStorage.IsolatedStorageFileStream..ctor(String path, FileMode mode, FileAccess access, FileShare share, Int32 bufferSize, IsolatedStorageFile isf)
    at System.IO.IsolatedStorage.IsolatedStorageFileStream..ctor(String path, FileMode mode, FileAccess access, FileShare share, IsolatedStorageFile isf)
    at IsolatedStorageFix.PackagingUtilities.SafeIsolatedStorageFileStream..ctor(String path, FileMode mode, FileAccess access, FileShare share, ReliableIsolatedStorageFileFolder folder) in .\PackagingUtilities.cs:line 576
    at IsolatedStorageFix.PackagingUtilities.ReliableIsolatedStorageFileFolder.GetStream(String fileName) in .\PackagingUtilities.cs:line 715
    at IsolatedStorageFix.PackagingUtilities.CreateUserScopedIsolatedStorageFileStreamWithRandomName(Int32 retryCount, String& fileName) in .\PackagingUtilities.cs:line 339
    at IsolatedStorageFix._Default.Page_Load(Object sender, EventArgs e) in .\Default.aspx.cs:line 30

After modifying the process token DACL, we can see both SIDs listed.  The process needs to restart (or wait until GC cleans up the mutex).

    Process token's default DACL:  
    - Identity: S-1-5-18  
    --- Access Type: AccessAllowed  
    --- Access Mask: 268435456  
    --- Inheritance Flags: None  
    --- Propagation Flags: None  
    - Identity: S-1-5-32-544  
    --- Access Type: AccessAllowed  
    --- Access Mask: 268435456  
    --- Inheritance Flags: None  
    --- Propagation Flags: None  
    - Identity: S-1-3-4  
    --- Access Type: AccessAllowed  
    --- Access Mask: 131072  
    --- Inheritance Flags: None  
    --- Propagation Flags: None  
    - Identity: S-1-5-82-4127829243-736442365-712821660-1652329799-1605461750  
    --- Access Type: AccessAllowed  
    --- Access Mask: 268435456  
    --- Inheritance Flags: None  
    --- Propagation Flags: None  
    - Identity: S-1-5-82-2677836526-1559996366-876931565-3569012157-1367525312  
    --- Access Type: AccessAllowed  
    --- Access Mask: 268435456  
    --- Inheritance Flags: None  
    --- Propagation Flags: None  
      
    CreateUserScopedIsolatedStorageFileStreamWithRandomName  
    Successfully created mutex.
