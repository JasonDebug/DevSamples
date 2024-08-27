#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

NET_LUID luid;

const char* GetAdapterType(ULONG IfType)
{
	switch (IfType)
	{
	case IF_TYPE_ETHERNET_CSMACD:
		return "Ethernet";
	case IF_TYPE_IEEE80211:
		return "Wireless LAN";
	case IF_TYPE_SOFTWARE_LOOPBACK:
		return "Loopback";
	case IF_TYPE_PPP:
		return "PPP";
	case IF_TYPE_TUNNEL:
		return "Tunnel";
	case IF_TYPE_IEEE1394:
		return "Firewire";
	default:
		return "Other";
	}
}

// Convert the physical adapter address to a human-readable hex format
std::string GetMacAddress(BYTE* addr, ULONG length)
{
	std::string macAddress;
	for (ULONG i = 0; i < length; i++)
	{
		char buffer[3]; // 2 digits + null terminator
		snprintf(buffer, sizeof(buffer), "%.2X", addr[i]);
		macAddress += buffer;

		if (i < (length - 1))
		{
			macAddress += "-";
		}
	}
	return macAddress;
}

// Displays adapter info similar to ipconfig
// Returns true if IPv6 address is found
bool DumpIPv6Config()
{
	// Check if IPv6 is supported
	DWORD dwRetVal = 0;
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG outBufLen = 15000;
	int Iterations = 0;
	bool ipv6Found = false;

	while ((dwRetVal = GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen)) == ERROR_BUFFER_OVERFLOW && ++Iterations < 3)
	{
		// Resizing the buffer based on outBufLen
		if (pAddresses != NULL)
			free(pAddresses);

		pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);

		// Check if the memory allocation failed
		if (pAddresses == NULL)
		{
			printf("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
			return false;
		}
	}

	if (dwRetVal != ERROR_SUCCESS)
	{
		printf("GetAdaptersAddresses failed with error: %d\n", dwRetVal);
		free(pAddresses);
		return false;
	}

	// Loop through the linked list of adapter addresses
	PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
	while (pCurrAddresses)
	{
		std::wcout << GetAdapterType(pCurrAddresses->IfType) << " adapter " << pCurrAddresses->FriendlyName << ":" << std::endl << std::endl;
		std::wcout << "   Media State . . . . . . . . . . . : " << (pCurrAddresses->OperStatus == IfOperStatusUp ? "Media disconnected" : "Media connected") << std::endl;
		std::wcout << "   Connection-specific DNS Suffix  . : " << pCurrAddresses->DnsSuffix << std::endl;
		std::wcout << "   Description . . . . . . . . . . . : " << pCurrAddresses->Description << std::endl;
		std::cout  << "   Physical Address. . . . . . . . . : " << GetMacAddress(pCurrAddresses->PhysicalAddress, pCurrAddresses->PhysicalAddressLength) << std::endl;
		std::wcout << "   Adapter ID (GUID) . . . . . . . . : " << pCurrAddresses->AdapterName << std::endl;

		// Assign luid to the loopback adapter so we can
		// later assign the IPv6 address to it
		if (pCurrAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
		{
			luid = pCurrAddresses->Luid;
		}

		PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
		while (pUnicast)
		{
			// Convert the IPv6 address to a readable format
			char ipStringBuffer[46]; // INET6_ADDRSTRLEN is 46
			DWORD ipStringBufferLength = 46;
			struct sockaddr_in6* sockaddr_ipv6 = (struct sockaddr_in6*)pUnicast->Address.lpSockaddr;

			inet_ntop(AF_INET6, &sockaddr_ipv6->sin6_addr, ipStringBuffer, ipStringBufferLength);

			// Determine the type of IPv6 address
			if (sockaddr_ipv6->sin6_addr.s6_addr[0] == 0xfe && sockaddr_ipv6->sin6_addr.s6_addr[1] == 0x80)
			{
				std::wcout << "   Link-local IPv6 Address . . . . . : " << ipStringBuffer;

				// Append the link-local scope id
				if (sockaddr_ipv6->sin6_scope_id != 0)
					std::wcout << "%" << sockaddr_ipv6->sin6_scope_id;
			}
			else if (pUnicast->Flags & IP_ADAPTER_ADDRESS_TRANSIENT || pUnicast->SuffixOrigin == NlsoRandom)
			{
				std::wcout << "   Temporary IPv6 Address. . . . . . : " << ipStringBuffer;
			}
			else if (sockaddr_ipv6->sin6_addr.s6_addr[0] == 0xfd)
			{
				std::wcout << "   Unique Local IPv6 Address (ULA) . : " << ipStringBuffer;
			}
			else
			{
				std::wcout << "   IPv6 Address. . . . . . . . . . . : " << ipStringBuffer;
			}

			if (pUnicast->DadState == NldsPreferred)
				std::wcout << " (Preferred)" << std::endl;
			else if (pUnicast->DadState == NldsTentative)
				std::wcout << " (Tentative)" << std::endl;
			else
				std::wcout << std::endl;

			ipv6Found = true;
			pUnicast = pUnicast->Next;
		}
		std::wcout << std::endl;
		pCurrAddresses = pCurrAddresses->Next;
	}

	free(pAddresses);
	return ipv6Found;
}

bool DeleteIPv6AddressFromAdapter(const NET_LUID& luid, const char* ipv6Address, const char* prefixLength)
{
	MIB_UNICASTIPADDRESS_ROW ipRow;
	InitializeUnicastIpAddressEntry(&ipRow);

	ipRow.InterfaceLuid = luid;
	ipRow.OnLinkPrefixLength = (UCHAR)atoi(prefixLength);

	// Convert the IPv6 address from text to binary form
	SOCKADDR_IN6 sockaddr = { 0 };
	sockaddr.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ipv6Address, &sockaddr.sin6_addr);
	ipRow.Address.Ipv6 = sockaddr;

	DWORD dwRetVal = DeleteUnicastIpAddressEntry(&ipRow);
	if (dwRetVal != NO_ERROR)
	{
		// Print the error message, but proceed to re-add the address
		std::wcout << "Failed to delete the existing IPv6 address. Error: " << dwRetVal << std::endl;
	}

	return true;
}


bool AddIPv6AddressToAdapter(const NET_LUID& luid, const char* ipv6Address, const char* prefixLength)
{
	// REF: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry

	// Remove the address if it already exists. Illustration purposes really, simplifies the sample
	DeleteIPv6AddressFromAdapter(luid, ipv6Address, prefixLength);

	MIB_UNICASTIPADDRESS_ROW ipRow;
	InitializeUnicastIpAddressEntry(&ipRow);

	// Set the Interface LUID to the one provided
	ipRow.InterfaceLuid = luid;
	ipRow.PrefixOrigin = IpPrefixOriginManual;
	ipRow.SuffixOrigin = IpSuffixOriginManual;
	ipRow.ValidLifetime = 0xffffffff;
	ipRow.PreferredLifetime = 0xffffffff;
	ipRow.OnLinkPrefixLength = (UCHAR)atoi(prefixLength);
	ipRow.DadState = IpDadStatePreferred;

	// Convert the IPv6 address from text to binary form
	SOCKADDR_IN6 sockaddr = { 0 };
	sockaddr.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ipv6Address, &sockaddr.sin6_addr);
	ipRow.Address.Ipv6 = sockaddr;

	// Add the unicast IP address entry to the system
	DWORD dwRetVal = CreateUnicastIpAddressEntry(&ipRow);

	if (dwRetVal != NO_ERROR)
	{
		std::wcout << "Failed to add the IPv6 address. Error: " << dwRetVal << std::endl;
		return false;
	}

	std::wcout << "IPv6 address added successfully." << std::endl;
	return true;
}

int main()
{
	std::boolalpha(std::cout);

	std::cout << "Windows IPv6 Configuration" << std::endl << std::endl;

	if (!DumpIPv6Config() || luid.Value == 0)
	{
		std::cout << "IPv6 is not supported" << std::endl;
		return 1;
	}

	// Assign a new IPv6 address to the loopback adapter
	// Note that luid is assigned in DumpIPv6Config()
	const char* ipv6Address = "2001:db8::1234"; // Example IPv6 address
	const char* prefixLength = "64"; // Example prefix length

	std::wcout << "Adding IPv6 address " << ipv6Address << " to loopback adapter...";
	if (AddIPv6AddressToAdapter(luid, ipv6Address, prefixLength))
	{
		std::wcout << std::endl;

		// Show the new config
		DumpIPv6Config();
	}
	else
	{
		std::cout << "Failed to configure IPv6 address: 0x" << std::hex << GetLastError() << std::endl << std::dec;
	}
}
