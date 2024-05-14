#using < System.Security.dll>
#using < System.Xml.dll>

using namespace System::Security::Cryptography;
using namespace System::Security::Cryptography::Xml;
using namespace System::Xml;

#include "Decrypt.h"

bool Decrypt::decryptData(BYTE* buffer, DWORD& lenData) {
    HCRYPTPROV cryptoProvider = 0;
    CryptAcquireContext(&cryptoProvider, NULL, NULL, PROV_RSA_AES,
                        CRYPT_VERIFYCONTEXT);
    HCRYPTKEY hKey = 0;
    HCRYPTKEY* phKey = &hKey;
    HCRYPTHASH hHash;
    LPCSTR password = "Password";
    DWORD error = 0;
    CryptCreateHash(cryptoProvider, CALG_SHA1, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)password,
                  (DWORD)_tcslen(password) * sizeof(TCHAR), 0);
    CryptDeriveKey(cryptoProvider, CALG_AES_256, hHash, CRYPT_CREATE_SALT,
                   &hKey);
    CryptDecrypt(hKey, NULL, TRUE, 0, buffer, &lenData);
    error = GetLastError();
    return !error;
}

bool Decrypt::verifySignature(LPCTSTR licenseFileName) {
    XmlDocument ^ xmlDocument = gcnew XmlDocument;
    xmlDocument->Load(gcnew System::String(licenseFileName));
    SignedXml ^ signedXml = gcnew SignedXml(xmlDocument);
    XmlNodeList ^ nodeList = xmlDocument->GetElementsByTagName("Signature");

    if (!nodeList->Item(0)) {
        return false;
    }

    signedXml->LoadXml(safe_cast<XmlElement ^>(nodeList->Item(0)));
    XmlNodeList ^ keyNodeList =
        xmlDocument->GetElementsByTagName("SignatureKey");
    XmlElement ^ keyElement = safe_cast<XmlElement ^>(keyNodeList->Item(0));

    if (!keyElement) {
        return false;
    }

    System::String ^ keyFromLicense = keyElement->InnerText;
    System::String ^ publicKey("");  // Key string
    if (keyFromLicense != publicKey) {
        return false;
    }
    RSACryptoServiceProvider ^ rsa = gcnew RSACryptoServiceProvider();
    rsa->FromXmlString(publicKey);
    return signedXml->CheckSignature(rsa);
}

bool Decrypt::findFileInLicense(LPCTSTR licenseFileName, LPCTSTR fileName) {
    System::String ^ strLicenseFileName = gcnew System::String(licenseFileName);
    System::String ^ ppFileName = gcnew System::String(fileName);

    XmlDocument ^ doc = gcnew XmlDocument;
    doc->Load(gcnew XmlTextReader(strLicenseFileName));

    XmlNodeList ^ ppFileList = doc->GetElementsByTagName("Files");
    XmlElement ^ ppFileElement = safe_cast<XmlElement ^>(ppFileList->Item(0));

    if (!ppFileElement) {
        return false;
    }

    for (int i = 0; i < ppFileElement->ChildNodes->Count; i++) {
        if ((ppFileElement->ChildNodes[i]->InnerText) == ppFileName) {
            return true;
        }
    }
    return false;
}

bool Decrypt::findClientIDInLicense(LPCTSTR licenseFileName, LPCTSTR ClientID) {
    XmlDocument ^ doc = gcnew XmlDocument;
    doc->Load(gcnew XmlTextReader(gcnew System::String(licenseFileName)));

    XmlNodeList ^ ClientIDList = doc->GetElementsByTagName("ClientID");
    XmlElement ^ ClientIDElement =
        safe_cast<XmlElement ^>(ClientIDList->Item(0));

    if (ClientIDElement) {
        return (ClientIDElement->InnerText == gcnew System::String(ClientID));
    }
    return false;
}

Decrypt::decryptionError Decrypt::decryptPPFile(LPCTSTR licenseFile,
                                                LPCTSTR encryptedPPFile,
                                                LPCTSTR ClientID,
                                                CMemFile& decryptedMemFile) {
    if (!System::IO::File::Exists(gcnew System::String(licenseFile))) {
        return LICENSE_FILE_NOT_FOUND;
    }

    if (!System::IO::File::Exists(gcnew System::String(encryptedPPFile))) {
        return POSTPROCESSOR_FILE_NOT_FOUND;
    }

    if (!findClientIDInLicense(licenseFile, ClientID)) {
        return INVALID_CLIENT_ID_IN_LICENSE;
    }

    if (!findFileInLicense(licenseFile, encryptedPPFile)) {
        return NO_ACCESS_TO_POSTPROCESSOR_FILE;
    }

    if (!verifySignature(licenseFile)) {
        return INVALID_SIGNATURE;
    }

    CFile encryptedFile;
    if (!encryptedFile.Open(
            encryptedPPFile,
            CFile::modeRead | CFile::shareDenyWrite | CFile::typeBinary,
            NULL)) {
        return FILE_READ_FAILED;
    }

    DWORD fileLength = encryptedFile.GetLength();
    BYTE* buffer = new BYTE[fileLength + 1];
    encryptedFile.Read(buffer, fileLength);

    if (!decryptData(buffer, fileLength)) {
        return DECRYPTION_FAILED;
    }

    std::string fileName(encryptedPPFile);
    unsigned int nameLength = fileName.rfind('.', fileName.length());
    fileName = fileName.substr(0, nameLength);
    std::string bufferFileName = fileName;

    memcpy((char*)bufferFileName.data(), buffer, nameLength);

    if (fileName != bufferFileName) {
        return INVALID_POSTPOCESSOR_FILE;
    }

    buffer[fileLength + 1] = '\0';
    decryptedMemFile.Write(buffer + nameLength, fileLength - nameLength + 1);
    decryptedMemFile.Flush();
    encryptedFile.Close();
    delete[] buffer;
    return NONE;
}

Decrypt::decryptionError Decrypt::decryptPPFile(LPCTSTR encryptedPPFile,
                                                CMemFile& decryptedMemFile) {
    CFile encryptedFile;
    if (!encryptedFile.Open(
            encryptedPPFile,
            CFile::modeRead | CFile::shareDenyWrite | CFile::typeBinary,
            NULL)) {
        return FILE_READ_FAILED;
    }

    DWORD fileLength = encryptedFile.GetLength();
    BYTE* buffer = new BYTE[fileLength + 1];
    encryptedFile.Read(buffer, fileLength);
    if (!decryptData(buffer, fileLength)) {
        return DECRYPTION_FAILED;
    }

    std::string fileName(encryptedPPFile);
    unsigned int nameLength = fileName.rfind('.', fileName.length());
    fileName = fileName.substr(0, nameLength);
    std::string bufferFileName = fileName;

    memcpy((char*)bufferFileName.data(), buffer, nameLength);

    if (fileName != bufferFileName) {
        return INVALID_POSTPOCESSOR_FILE;
    }
    buffer[fileLength + 1] = '\0';

    decryptedMemFile.Write(buffer + nameLength, fileLength - nameLength + 1);
    decryptedMemFile.Flush();
    encryptedFile.Close();
    delete[] buffer;
    return NONE;
}
