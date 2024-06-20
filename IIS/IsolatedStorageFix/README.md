The IsolatedStorage store is locked when in use, and we use Mutexes to do so.  It is important to have an understanding of the statements below:

- When the application starts, it modifies the default DACL for the process to include SYSTEM, Administrators, OWNER, and itself (the current w3wp instance).  This is done to enhance security as we have an inclusive list that's fairly minimal.
- The mutex used by IsolatedStorage is created with the same ACL as the Default DACL for the process.
- The IsolatedStorage store is unique per user, so if the same service account is used to run multiple applications the store will be shared across them.  ApplicationPoolIdentity is unaffected as it's effectively SYSTEM.
- Multiple instances of an application running under the same application pool will run in the same w3wp.exe instance by default.
- A mutex will be reused if it is open, retaining its current ACL.

**What's the Issue?**

Taking all the above into account, when we have multiple application pools running with the same service account, IsolatedStorage can fail.  This is because if those pools try to access the store at the same time the mutex will not contain the other application's SID and it will be restricted from access.  This is generally only going to be a problem for long-running operations in IsolatedStorage as the mutex is disposed after we're done with the store.

**Mitigation**

There are multiple ways to mitigate the above issue:

- Use the same application pool for applications that need to use the same service account.
- Use a different service account for each application pool.
- Modify the process token's Default DACL to include the SIDs for the other application pools that need access to the same service account's IsolatedStorage store.  This code demonstrates that.
