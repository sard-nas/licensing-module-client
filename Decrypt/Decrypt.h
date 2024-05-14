#pragma once
#define _AFXDLL

#include <afx.h>
#include <windows.h>
#include <Wincrypt.h>
#include <string>

class Decrypt
{
private:
	bool DecryptData(BYTE* buffer, DWORD& lenData);
	bool VerifySignature(LPCTSTR licenseFileName);
	bool FindFileInLicense(LPCTSTR licenseFileName, LPCTSTR fileName);
	bool FindClientIDInLicense(LPCTSTR licenseFileName, LPCTSTR ClientID);

public:
	enum  decryptionError{NONE, LICENSE_FILE_NOT_FOUND, POSTPROCESSOR_FILE_NOT_FOUND, INVALID_CLIENT_ID_IN_LICENSE, NO_ACCESS_TO_POSTPROCESSOR_FILE, INVALID_SIGNATURE, FILE_READ_FAILED, DECRYPTION_FAILED, INVALID_POSTPOCESSOR_FILE};
	//decription without signature verification
	decryptionError DecryptPPFile(LPCTSTR encryptedPPFile, CMemFile& decryptedMemFile);
	//decription with signature verification
	decryptionError DecryptPPFile(LPCTSTR licenseFile, LPCTSTR nameSource, LPCTSTR ClientID, CMemFile& nameDest);
};

