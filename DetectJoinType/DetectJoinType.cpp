#include <windows.h>
#include <lm.h>
#include <lmjoin.h>
#include <iostream>
#pragma comment(lib, "Netapi32.lib")

void DetectJoinStatus();

int main()
{
    DetectJoinStatus();
}

void DetectJoinStatus() {
    // Check for Domain or Workgroup (traditional)
    LPWSTR nameBuffer = nullptr;
    NETSETUP_JOIN_STATUS joinStatus;
    if (NetGetJoinInformation(NULL, &nameBuffer, &joinStatus) == NERR_Success) {
        if (joinStatus == NetSetupDomainName) {
            std::wcout << L"Domain Joined: " << nameBuffer << std::endl;
        }
        else if (joinStatus == NetSetupWorkgroupName) {
            std::wcout << L"Workgroup: " << nameBuffer << std::endl;
        }
        else {
            std::wcout << L"Join status: Unknown" << std::endl;
        }
        NetApiBufferFree(nameBuffer);
    }
    else {
        std::wcout << L"NetGetJoinInformation failed" << std::endl;
    }

    // Check Microsoft Entra ID join info
    PDSREG_JOIN_INFO pJoinInfo = nullptr;
    if (NetGetAadJoinInformation(nullptr, &pJoinInfo) == NERR_Success) {
        if (pJoinInfo) {
            switch (pJoinInfo->joinType) {
            case DSREG_DEVICE_JOIN:
                std::wcout << L"Microsoft Entra Joined (Device Join). Tenant ID: "
                    << pJoinInfo->pszTenantId << std::endl;
                break;
            case DSREG_WORKPLACE_JOIN:
                std::wcout << L"Workplace Joined (MSA or BYOD)" << std::endl;
                break;
            case DSREG_UNKNOWN_JOIN:
            default:
                std::wcout << L"Not Azure AD Joined" << std::endl;
                break;
            }
            NetFreeAadJoinInformation(pJoinInfo);
        }
    }
    else {
        std::wcout << L"NetGetAadJoinInformation not supported or failed" << std::endl;
    }
}
