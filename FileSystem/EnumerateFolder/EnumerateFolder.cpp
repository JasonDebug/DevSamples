#include <windows.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <directoryPath>\n";
        return 1;
    }

    // Get the dir path and build the search pattern
    std::string dir = argv[1];
    std::string search = dir;
    char last = search.back();
    if (last == ':' || last == '\\') {
        search += '*';
    }
    else {
        search += "\\*";
    }
	
    std::cout << "Searching: " << search << "\n";

    // FindFirstFile
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(search.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_DIRECTORY) {
            std::cerr << "Not a directory: " << dir << "\n";
        }
        else {
            std::cerr << "FindFirstFile failed (error " << err << ")\n";

			// Write out the error message
            LPVOID lpMsgBuf;
            FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                NULL,
                err,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&lpMsgBuf,
                0, NULL);
            std::cerr << "Error message: " << (char*)lpMsgBuf << "\n";
			LocalFree(lpMsgBuf);
        }
        return 1;
    }

    std::cout << "First entry in \"" << dir << "\": "
        << findData.cFileName << "\n";

	// Enumerate the rest of the directory
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::cout << "Directory: ";
        } else {
            std::cout << "File: ";
        }
        std::cout << findData.cFileName << "\n";
	} while (FindNextFileA(hFind, &findData) != 0);

    FindClose(hFind);
    return 0;
}
