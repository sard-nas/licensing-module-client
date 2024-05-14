#define _AFXDLL

#include <afx.h>
#include <windows.h>
#include <Wincrypt.h>
#include <iostream>
#include <tchar.h>
#include "Decrypt.h"



void readMemFile(CMemFile& mf)
{
	mf.SeekToEnd();
	DWORD fileLength = mf.GetPosition();
	mf.SeekToBegin();
	BYTE* buffer = new BYTE[fileLength];
	mf.Read(buffer, fileLength);
	std::cout << "\nMemfile: " << buffer;
	delete[] buffer;
}


int main()
{
	CMemFile mf;
	Decrypt d;

	//Decrypt .smx file with verification license file for Client_ID 1:
	std::cout << "Error:\n" << d.DecryptPPFile("licence_file.xml", "postpocessor_file.smx", "1", mf) << std::endl;

	//Decrypt file without verification license:
	std::cout << "Error:\n" << d.DecryptPPFile("postpocessor_file.smx", mf) << std::endl;
	
	readMemFile(mf);	//print result
	system("pause");
	return 0;
}