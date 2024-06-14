/*********************************************************************************
* MIT License                                                                    *
*                                                                                *
* Copyright (c) 2022 Jason                                                       *
*                                                                                *
* Permission is hereby granted, free of charge, to any person obtaining a copy   *
* of this software and associated documentation files (the "Software"), to deal  *
* in the Software without restriction, including without limitation the rights   *
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      *
* copies of the Software, and to permit persons to whom the Software is          *
* furnished to do so, subject to the following conditions:                       *
*                                                                                *
* The above copyright notice and this permission notice shall be included in all *
* copies or substantial portions of the Software.                                *
*                                                                                *
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     *
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       *
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    *
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         *
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  *
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  *
* SOFTWARE.                                                                      *
**********************************************************************************/

#include <windows.h>
#include <wintrust.h>
#include <Softpub.h>
#include <mscat.h>
#include <wincrypt.h>
#include <iostream>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// Convert a hash to a hexadecimal string
std::string ConvertHashToHexString(const BYTE* hash, DWORD hashSize)
{
    std::string result;
    char buf[3];
    for (DWORD i = 0; i < hashSize; ++i)
    {
        sprintf_s(buf, sizeof(buf), "%02X", hash[i]);
        result += buf;
    }
    return result;
}

// Display certificate information on screen
void DisplayCertificateInfo(PCCERT_CONTEXT pCertContext)
{
    char szName[256];
    if (CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szName, sizeof(szName)))
    {
        std::cout << "Subject: " << szName << std::endl;
    }

    if (CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, szName, sizeof(szName)))
    {
        std::cout << "Issuer: " << szName << std::endl;
    }

    std::cout << "Serial Number: ";
    for (DWORD i = 0; i < pCertContext->pCertInfo->SerialNumber.cbData; ++i)
    {
        printf("%02X", pCertContext->pCertInfo->SerialNumber.pbData[pCertContext->pCertInfo->SerialNumber.cbData - (i + 1)]);
    }
    std::cout << std::endl;

    FILETIME ft;
    SYSTEMTIME st;
    ft = pCertContext->pCertInfo->NotBefore;
    FileTimeToSystemTime(&ft, &st);
    std::cout << "Valid From: " << st.wMonth << "/" << st.wDay << "/" << st.wYear << std::endl;

    ft = pCertContext->pCertInfo->NotAfter;
    FileTimeToSystemTime(&ft, &st);
    std::cout << "Valid To: " << st.wMonth << "/" << st.wDay << "/" << st.wYear << std::endl;
}

// Verify the certificate chain
bool VerifyCertificateChain(PCCERT_CONTEXT pCertContext)
{
    CERT_CHAIN_PARA chainPara = { sizeof(chainPara) };
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;

    if (!CertGetCertificateChain(NULL, pCertContext, NULL, pCertContext->hCertStore, &chainPara, 0, NULL, &pChainContext))
    {
        std::cout << "CertGetCertificateChain failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Verify the chain
    CERT_CHAIN_POLICY_PARA policyPara = { sizeof(policyPara) };
    CERT_CHAIN_POLICY_STATUS policyStatus = { sizeof(policyStatus) };

    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, pChainContext, &policyPara, &policyStatus))
    {
        std::cout << "CertVerifyCertificateChainPolicy failed. Error: " << GetLastError() << std::endl;
        CertFreeCertificateChain(pChainContext);
        return false;
    }

    if (policyStatus.dwError != 0)
    {
        std::cout << "CertVerifyCertificateChainPolicy failed. Policy Status Error: " << policyStatus.dwError << std::endl;
        CertFreeCertificateChain(pChainContext);
        return false;
    }

    std::cout << "Certificate chain verified successfully." << std::endl;
    CertFreeCertificateChain(pChainContext);
    return true;
}

// Verify the signature on the catalog file and display the certificate details
bool VerifyCatSignature(const wchar_t* catFilePath)
{
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = catFilePath;
    fileInfo.hFile = NULL;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags = WTD_USE_DEFAULT_OSVER_CHECK;

    GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust
    LONG status = WinVerifyTrust(NULL, &actionGUID, &winTrustData);
    if (status != ERROR_SUCCESS)
    {
        std::cout << "WinVerifyTrust failed. Error: " << status << std::endl;
        return false;
    }

    // Retrieve the trust provider information from the state data
    // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelperprovdatafromstatedata
    CRYPT_PROVIDER_DATA* pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
    if (!pProvData)
    {
        std::cout << "WTHelperProvDataFromStateData failed." << std::endl;
        return false;
    }

    // Retrieve the signer information from the provider data
    // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain
    CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
    if (!pProvSigner)
    {
        std::cout << "WTHelperGetProvSignerFromChain failed." << std::endl;
        return false;
    }

    // Display the signing certificate
    PCCERT_CONTEXT pCertContext = pProvSigner->pasCertChain->pCert;
    DisplayCertificateInfo(pCertContext);
    VerifyCertificateChain(pCertContext);

    // Check for countersignature and display it as well
    if (pProvSigner->csCounterSigners > 0)
    {
        CRYPT_PROVIDER_SGNR* pCounterSigner = WTHelperGetProvSignerFromChain(pProvData, 0, TRUE, 0);
        if (pCounterSigner)
        {
            PCCERT_CONTEXT pCounterCertContext = pCounterSigner->pasCertChain->pCert;
            std::cout << "Countersigner Certificate Info:" << std::endl;
            DisplayCertificateInfo(pCounterCertContext);
            VerifyCertificateChain(pCounterCertContext);
        }
    }

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGUID, &winTrustData);

    return true;
}

// The main work method to get the certificate information
bool GetFileCertificate(const wchar_t* filePath)
{
    // Open the file we want to verify
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to open file. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Acquire a handle to the catalog administrator context
    // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadminacquirecontext
    HCATADMIN hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
    {
        std::cout << "CryptCATAdminAcquireContext failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // First, call CryptCATAdminCalcHashFromFileHandle to get the hash size
    // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadmincalchashfromfilehandle
    DWORD hashSize = 0;
    CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        std::cout << "CryptCATAdminCalcHashFromFileHandle failed to get the buffer size. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    // Allocate buffer for the hash using the hash size from the previous call to CryptCATAdminCalcHashFromFileHandle
    BYTE* hash = new BYTE[hashSize];
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash, 0))
    {
        std::cout << "CryptCATAdminCalcHashFromFileHandle failed. Error: " << GetLastError() << std::endl;
        delete[] hash;
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    // We no longer need the handle to the file
    CloseHandle(hFile);

    // Display the calculated hash
    std::string hashHexString = ConvertHashToHexString(hash, hashSize);
    std::cout << "PESHA1 File Hash: " << hashHexString << std::endl;

    // Enumerate the catalog files that contain the specified hash
    // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadminenumcatalogfromhash
    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, NULL);
    if (hCatInfo == NULL)
    {
        std::cout << "CryptCATAdminEnumCatalogFromHash failed. Error: " << GetLastError() << std::endl;
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    // Get the catalog information from the context (namely the catalog file path)
    // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatcataloginfofromcontext
    CATALOG_INFO catInfo = { 0 };
    catInfo.cbStruct = sizeof(CATALOG_INFO);

    if (!CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
    {
        std::cout << "CryptCATCatalogInfoFromContext failed. Error: " << GetLastError() << std::endl;
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    // Display the catalog file path
    std::wcout << L"Catalog File Path: " << catInfo.wszCatalogFile << std::endl;

    // Verify and display the signature from the catalog file
    bool result = VerifyCatSignature(catInfo.wszCatalogFile);

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    delete[] hash;

    return result;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        std::wcout << L"Usage: " << argv[0] << L" <path_to_executable>" << std::endl;
        return 1;
    }

    if (!GetFileCertificate(argv[1]))
    {
        std::wcout << L"Failed to get certificate information." << std::endl;
        return 1;
    }

    return 0;
}
