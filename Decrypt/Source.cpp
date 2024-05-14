#define _AFXDLL

#include <Wincrypt.h>
#include <afx.h>
#include <tchar.h>
#include <windows.h>

#include <iostream>

#include "Decrypt.h"

void readMemFile(CMemFile& mf) {
    mf.SeekToEnd();
    DWORD fileLength = mf.GetPosition();
    mf.SeekToBegin();
    BYTE* buffer = new BYTE[fileLength];
    mf.Read(buffer, fileLength);
    std::cout << "\nMemfile: " << buffer;
    delete[] buffer;
}

int main() {
    CMemFile mf;
    Decrypt d;
    std::cout << "Error:\n"
              << d.decryptPPFile("licence_file.xml", "postpocessor_file.smx",
                                 "1", mf)
              << std::endl;
    readMemFile(mf);
    system("pause");
    return 0;
}