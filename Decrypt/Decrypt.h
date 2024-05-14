#pragma once
#define _AFXDLL

#include <Wincrypt.h>
#include <afx.h>
#include <windows.h>

#include <string>

class Decrypt {
   private:
    bool decryptData(BYTE* buffer, DWORD& lenData);
    bool verifySignature(LPCTSTR licenseFileName);
    bool findFileInLicense(LPCTSTR licenseFileName, LPCTSTR fileName);
    bool findClientIDInLicense(LPCTSTR licenseFileName, LPCTSTR ClientID);

   public:
    enum decryptionError {
        NONE,
        LICENSE_FILE_NOT_FOUND,
        POSTPROCESSOR_FILE_NOT_FOUND,
        INVALID_CLIENT_ID_IN_LICENSE,
        NO_ACCESS_TO_POSTPROCESSOR_FILE,
        INVALID_SIGNATURE,
        FILE_READ_FAILED,
        DECRYPTION_FAILED,
        INVALID_POSTPOCESSOR_FILE
    };
    decryptionError decryptPPFile(LPCTSTR encryptedPPFile,
                                  CMemFile& decryptedMemFile);
    decryptionError decryptPPFile(LPCTSTR licenseFile, LPCTSTR nameSource,
                                  LPCTSTR ClientID, CMemFile& nameDest);
};
