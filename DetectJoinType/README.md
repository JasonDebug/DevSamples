DetectJoinType is a simple tool to detect whether the machine is part of a domain, workgroup, un-joined, or Azure Entra joined.

It uses two APIs:

#### NetGetJoinInformation
- https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetjoininformation
- The NetGetJoinInformation function retrieves join status information for the specified computer.

#### NetGetAadJoinInformation
- https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation
- Retrieves the join information for the specified tenant. This function examines the join information for Microsoft Entra ID and the work account that the current user added.