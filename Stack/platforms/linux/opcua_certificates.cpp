/* ========================================================================
 * Copyright (c) 2005-2010 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Reciprocal Community License ("RCL") Version 1.00
 *
 * Unless explicitly acquired and licensed from Licensor under another
 * license, the contents of this file are subject to the Reciprocal
 * Community License ("RCL") Version 1.00, or subsequent versions as
 * allowed by the RCL, and You may not copy or use this file in either
 * source code or executable form, except in compliance with the terms and
 * conditions of the RCL.
 *
 * All software distributed under the RCL is provided strictly on an
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RCL for specific
 * language governing rights and limitations under the RCL.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/RCL/1.00/
 * ======================================================================*/

// TODO
//#define WIN32_LEAN_AND_MEAN

#include <opcua_platformdefs.h>
#include <opcua_p_types.h>
//#include <opcua_builtintypes.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
//#include <netinet/in.h>
//#include <netinet/tcp.h>
#include <errno.h>
//#include <fcntl.h>
#include <dirent.h>

#include <string>
#include <vector>
#include <cstdlib>


#include <opcua.h>
#include <opcua_core.h>
#include <opcua_certificates.h>
#include <opcua_trace.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/conf.h>

//static char OID_AUTHORITY_KEY_IDENTIFIER[] = { 85, 29, 1 };
static char OID_SUBJECT_ALT_NAME[] = { 85, 29, 7 };

/*============================================================================
 * OpcUa_ReadFile
 *===========================================================================*/
OpcUa_StatusCode OpcUa_ReadFile(
	OpcUa_StringA		a_sFilePath,
	OpcUa_ByteString* a_pBuffer)
{
	FILE* pFile = NULL;
	OpcUa_Byte* pBuffer = NULL;
	int iResult = 0;
	size_t iLength = 0;
	OpcUa_Byte* pPosition = OpcUa_Null;


OpcUa_InitializeStatus(OpcUa_Module_Utilities, "OpcUa_ReadFile");

	OpcUa_ReturnErrorIfArgumentNull(a_sFilePath);
	OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);

	OpcUa_ByteString_Initialize(a_pBuffer);

	// read the file.
	pFile = fopen((const char*)a_sFilePath, "rb");

	if (iResult == OpcUa_Null)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	// get the length,
	iResult = fseek(pFile, 0, SEEK_END);

	if (iResult == 0)
	{
		iLength = ftell(pFile);

//		if (iResult != 0)
//		{
//			OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
//		}

		fseek(pFile, 0, SEEK_SET);
	}

	// allocate buffer.
	pBuffer = (OpcUa_Byte*)OpcUa_Alloc((OpcUa_UInt32)iLength);
	memset(pBuffer, 0, iLength);

	// read blocks.
	pPosition = pBuffer;

	while (pFile != NULL)
	{
		iResult = fread(pPosition, 1, (size_t)(iLength-(pPosition-pBuffer)), pFile);

		if (iResult <= 0)
		{
			break;
		}

		pPosition += iResult;
	}

	fclose(pFile);
	pFile = NULL;

	a_pBuffer->Data   = pBuffer;
	a_pBuffer->Length = pPosition - pBuffer;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pFile != OpcUa_Null)
	{
		fclose(pFile);
	}

	if (pBuffer != OpcUa_Null)
	{
		OpcUa_Free(pBuffer);
	}

	OpcUa_ByteString_Initialize(a_pBuffer);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WriteFile
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WriteFile(
	OpcUa_StringA  a_sFilePath,
	OpcUa_Byte*	a_pBuffer,
	OpcUa_UInt32   a_uBufferLength)
{
	FILE* pFile = NULL;
	int iResult = 0;

OpcUa_InitializeStatus(OpcUa_Module_Utilities, "OpcUa_WriteFile");

	OpcUa_ReturnErrorIfArgumentNull(a_sFilePath);
	OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);

	pFile = fopen((const char*)a_sFilePath, "wb");

	if (pFile == OpcUa_Null)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	iResult = fwrite(a_pBuffer, 1, (size_t)a_uBufferLength, pFile);

	if (iResult <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	fclose(pFile);
	pFile = NULL;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pFile != OpcUa_Null)
	{
		fclose(pFile);
	}

OpcUa_FinishErrorHandling;
}

///*============================================================================
// * OpcUa_StringToUnicode
// *===========================================================================*/
//OpcUa_StatusCode OpcUa_StringToUnicode(
//	OpcUa_StringA a_sSource,
//	OpcUa_Char**  a_pUnicode)
//{
//	int iLength = 0;
//OpcUa_InitializeStatus(OpcUa_Module_Utilities, "OpcUa_StringToUnicode");
//
//	OpcUa_ReturnErrorIfArgumentNull(a_pUnicode);
//
//	*a_pUnicode = OpcUa_Null;
//
//	if (a_sSource == OpcUa_Null)
//	{
//		return OpcUa_Good;
//	}
//
//	iLength = wcstombs(NULL, a_sSource, 0);
//
//	if (iLength == 0)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
//	}
//
//	*a_pUnicode = (OpcUa_Char*)OpcUa_Alloc(sizeof(OpcUa_Char)*(iLength+1));
//
//	iLength = wcstombs(*a_pUnicode, a_sSource, iLength);
//
//	if (iLength == 0)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
//	}
//
//	(*a_pUnicode)[iLength] = L'\0';
//
//OpcUa_ReturnStatusCode;
//OpcUa_BeginErrorHandling;
//
//	if (*a_pUnicode != OpcUa_Null)
//	{
//		OpcUa_Free(*a_pUnicode);
//		*a_pUnicode = OpcUa_Null;
//	}
//
//OpcUa_FinishErrorHandling;
//}

/*============================================================================
 * OpcUa_Certificate_CopyStrings
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_CopyStrings(
	std::vector<std::string> src,
	OpcUa_StringA**			pStrings,
	OpcUa_UInt32*			pNoOfStrings)
{
	int iLength = 0;
OpcUa_InitializeStatus(OpcUa_Module_Utilities, "OpcUa_Certificate_CopyStrings");

	OpcUa_ReturnErrorIfArgumentNull(pStrings);
	OpcUa_ReturnErrorIfArgumentNull(pNoOfStrings);

	*pStrings = NULL;
	*pNoOfStrings = src.size();

	iLength = src.size()*sizeof(OpcUa_StringA);
	*pStrings = (OpcUa_StringA*)OpcUa_Alloc(iLength);
	OpcUa_GotoErrorIfAllocFailed(*pStrings);
	OpcUa_MemSet(*pStrings, 0, iLength);

	for (unsigned int ii = 0; ii < src.size(); ii++)
	{
		iLength = src[ii].size()+1;
		(*pStrings)[ii] = (OpcUa_StringA)OpcUa_Alloc(iLength);
		OpcUa_GotoErrorIfAllocFailed((*pStrings)[ii]);
		strcpy((*pStrings)[ii], src[ii].c_str());
	}

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (*pStrings != NULL)
	{
		for (unsigned int ii = 0; ii < *pNoOfStrings; ii++)
		{
			OpcUa_Free((*pStrings)[ii]);
		}

		OpcUa_Free(*pStrings);
		*pStrings = NULL;
		*pNoOfStrings = 0;
	}

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_CreateCryptoProviders
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_CreateCryptoProviders(
	OpcUa_PKIProvider* a_pPkiProvider,
	OpcUa_CryptoProvider* a_pCryptoProvider)
{
	OpcUa_P_OpenSSL_CertificateStore_Config tPkiConfiguration;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_FindCertificateInWindowsStore");

	OpcUa_ReturnErrorIfArgumentNull(a_pPkiProvider);
	OpcUa_ReturnErrorIfArgumentNull(a_pCryptoProvider);

	OpcUa_MemSet(a_pPkiProvider, 0, sizeof(OpcUa_PKIProvider));
	OpcUa_MemSet(a_pCryptoProvider, 0, sizeof(OpcUa_CryptoProvider));

	// create the certificate in an OpenSSL store.
	tPkiConfiguration.PkiType							= OpcUa_OpenSSL_PKI;
	tPkiConfiguration.Flags								= 0;
	tPkiConfiguration.CertificateRevocationListLocation = NULL;
	tPkiConfiguration.CertificateTrustListLocation		= NULL;

	uStatus = OpcUa_PKIProvider_Create(&tPkiConfiguration, a_pPkiProvider);
	OpcUa_GotoErrorIfBad(uStatus);

	// create the provider.
	uStatus = OpcUa_CryptoProvider_Create((OpcUa_StringA)OpcUa_SecurityPolicy_Basic128Rsa15, a_pCryptoProvider);
	OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_CryptoProvider_Delete(a_pCryptoProvider);
	OpcUa_PKIProvider_Delete(a_pPkiProvider);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_DeleteCryptoProviders
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_DeleteCryptoProviders(
	OpcUa_PKIProvider* a_pPkiProvider,
	OpcUa_CryptoProvider* a_pCryptoProvider)
{
OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_DeleteCryptoProviders");

	OpcUa_ReturnErrorIfArgumentNull(a_pPkiProvider);
	OpcUa_ReturnErrorIfArgumentNull(a_pCryptoProvider);

	OpcUa_CryptoProvider_Delete(a_pCryptoProvider);
	OpcUa_PKIProvider_Delete(a_pPkiProvider);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	// nothing to do.

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_GetFilePathForCertificate
 *===========================================================================*/
static std::string OpcUa_Certificate_GetFilePathForCertificate(
	OpcUa_StringA		a_sStorePath,
	OpcUa_ByteString*  a_pCertificate,
	OpcUa_P_FileFormat a_eFileFormat,
	OpcUa_Boolean		a_bCreateAlways)
{
	OpcUa_StringA sCommonName;
	OpcUa_StringA sThumbprint;
	std::string filePath;
	char* pPos = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_GetFilePathForCertificate");

	OpcUa_GotoErrorIfArgumentNull(a_sStorePath);
	OpcUa_GotoErrorIfArgumentNull(a_pCertificate);

	uStatus = OpcUa_Certificate_GetCommonName(a_pCertificate, &sCommonName);
	OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OpcUa_Certificate_GetThumbprint(a_pCertificate, &sThumbprint);
	OpcUa_GotoErrorIfBad(uStatus);

	// build file path.
	filePath = a_sStorePath;

	if (a_eFileFormat == OpcUa_Crypto_Encoding_DER)
	{
		filePath += DIR_SEPARATOR"certs"DIR_SEPARATOR;
	}
	else
	{
		filePath += DIR_SEPARATOR"private"DIR_SEPARATOR;
	}

	if (a_bCreateAlways)
	{
		for (unsigned int ii = 0; ii < filePath.size(); ii++)
		{
			char ch = filePath[ii];

			if (ch != '/' && ch != '\\')
			{
				continue;
			}

			std::string parent = filePath.substr(0, ii);

			if (parent.empty() || parent.size() <= 0 || parent[parent.size()-1] == ':')
			{
				continue;
			}

			// TODO
			/*
			S_IRWXU 00700 mask for file owner permissions
			S_IRUSR 00400 owner has read permission
			S_IWUSR 00200 owner has write permission
			S_IXUSR 00100 owner has execute permission
			S_IRWXG 00070 mask for group permissions
			S_IRGRP 00040 group has read permission
			S_IWGRP 00020 group has write permission
			S_IXGRP 00010 group has execute permission
			S_IRWXO 00007 mask for permissions for others (not in group)
			S_IROTH 00004 others have read permission
			S_IWOTH 00002 others have write permisson
			S_IXOTH 00001 others have execute permission
			*/
			if (!mkdir(parent.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH))
			{
				if (EEXIST != errno)
				{
					OpcUa_GotoErrorWithStatus(OpcUa_BadUserAccessDenied);
				}
			}
		}
	}

	// remove any special characters.
	pPos = sCommonName;

	while (*pPos != '\0')
	{
		char* pMatch = (char*)"<>:\"/\\|?*";

		while (*pMatch != '\0')
		{
			if (*pMatch == *pPos)
			{
				*pPos = '+';
				break;
			}

			pMatch++;
		}

		pPos++;
	}

	filePath += sCommonName;
	filePath += " [";
	filePath += sThumbprint;
	filePath += "]";

	// select the appropriate extension.
	switch(a_eFileFormat)
	{
		case OpcUa_Crypto_Encoding_DER:
		{
			filePath += ".der";
			break;
		}

		case OpcUa_Crypto_Encoding_PEM:
		{
			filePath += ".pem";
			break;
		}

		case OpcUa_Crypto_Encoding_PKCS12:
		{
			filePath += ".pfx";
			break;
		}

		default:
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
		}
	}

	OpcUa_Free(sCommonName);
	OpcUa_Free(sThumbprint);

	return filePath;

OpcUa_BeginErrorHandling;

	OpcUa_Free(sCommonName);
	OpcUa_Free(sThumbprint);

	return filePath;
}

/*============================================================================
 * OpcUa_Certificate_Create
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Certificate_Create(
	OpcUa_StringA		a_sStorePath,
	OpcUa_StringA		a_sApplicationName,
	OpcUa_StringA		a_sApplicationUri,
	OpcUa_StringA		a_sOrganization,
	OpcUa_StringA		a_sSubjectName,
	OpcUa_UInt32		a_uNoOfDomainNames,
	OpcUa_StringA*		a_pDomainNames,
	OpcUa_UInt32		a_uKeyType,
	OpcUa_UInt32		a_uKeySize,
	OpcUa_UInt32		a_uLifetimeInMonths,
	OpcUa_Boolean		a_bIsCA,
	OpcUa_P_FileFormat a_eFileFormat,
	OpcUa_ByteString*  a_pIssuerCertificate,
	OpcUa_Key*			a_pIssuerPrivateKey,
	OpcUa_StringA		a_sPassword,
	OpcUa_ByteString*  a_pCertificate,
	OpcUa_StringA*		a_pCertificateFilePath,
	OpcUa_Key*			a_pPrivateKey,
	OpcUa_StringA*		a_pPrivateKeyFilePath)
{
	OpcUa_CryptoProvider tCryptoProvider;
	OpcUa_PKIProvider tPkiProvider;

	OpcUa_UInt32 tvalidToInSec;

	OpcUa_Key tPublicKey;
	OpcUa_Crypto_NameEntry* pSubjectNameFields = OpcUa_Null;
	OpcUa_Crypto_Extension pExtensions[10];

	OpcUa_Certificate* pX509IssuerCertificate = OpcUa_Null;
	OpcUa_StringA pDomainName = OpcUa_Null;

	std::string domainName;
	std::string applicationUri;
	std::string subjectAltName;
	std::vector<std::string> domainNames;
	std::vector<std::string> fieldNames;
	std::vector<std::string> fieldValues;
	std::string subjectName;
	int iResult = 0;

	OpcUa_Byte* pPosition = NULL;
	OpcUa_Key* pPrivateKey = NULL;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_Create");

	OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
	OpcUa_ReturnErrorIfArgumentNull(a_sApplicationName)
	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

	OpcUa_ByteString_Initialize(a_pCertificate);
	OpcUa_Key_Initialize(a_pPrivateKey);

	if (a_pCertificateFilePath != NULL) *a_pCertificateFilePath = NULL;
	if (a_pPrivateKeyFilePath != NULL) *a_pPrivateKeyFilePath = NULL;

	OpcUa_MemSet(&tCryptoProvider, 0, sizeof(OpcUa_CryptoProvider));
	OpcUa_MemSet(&tPkiProvider, 0, sizeof(OpcUa_PKIProvider));
	OpcUa_Key_Initialize(&tPublicKey);
	OpcUa_MemSet(&pExtensions, 0, sizeof(pExtensions));
	OpcUa_ByteString_Initialize(a_pCertificate);
	OpcUa_Key_Initialize(a_pPrivateKey);

	// set default key type.
	if (a_uKeyType == 0)
	{
		a_uKeyType = OpcUa_Crypto_Rsa_Id;
	}

	// fill in list of host names.
	if (a_uNoOfDomainNames > 0)
	{
		for (unsigned int ii = 0; ii < a_uNoOfDomainNames; ii++)
		{
			if (a_pDomainNames[ii] != OpcUa_Null)
			{
				domainNames.push_back(a_pDomainNames[ii]);
			}
		}
	}

	// ensure at least one host is specified.
	if (domainNames.size() <= 0)
	{
		// look up the domain name for the current machine.
		uStatus = OpcUa_Certificate_LookupDomainName((OpcUa_StringA)"127.0.0.1", &pDomainName);

		// use the computer name if no domain name.
		if (OpcUa_IsBad(uStatus))
		{
			char sBuffer[MAX_PATH+1];
			size_t dwBufferLenth = MAX_PATH;
			gethostname(sBuffer, dwBufferLenth);
			domainName = sBuffer;
		}

		// copy the domain name.
		else
		{
			domainName = pDomainName;
			OpcUa_Free(pDomainName);
		}

		domainNames.push_back(domainName);
	}

	// generate an application uri.
	if (a_sApplicationUri == NULL || strlen(a_sApplicationUri) <= 0)
	{
		applicationUri = "urn:";
		applicationUri += domainNames[0];
		applicationUri += ":";
		applicationUri += a_sApplicationName;
	}
	else
	{
		applicationUri = a_sApplicationUri;
	}

	// remove invalid chars from uri.
	if (applicationUri.size() > 0)
	{
		int length = applicationUri.size();
		std::string updated;

		for (int ii = 0; ii < length; ii++)
		{
			unsigned char ch = applicationUri[ii];

			bool escape = !isprint(ch) || ch == '%' || ch == ',';

			if (escape)
			{
				char szBuf[4];
				sprintf(szBuf, "%%%2X", ch);
				updated += szBuf;
			}
			else
			{
				if (isspace(ch))
				{
					updated += ' ';
				}
				else
				{
					updated += ch;
				}
			}
		}

		applicationUri = updated;
	}

	// parse the subject name.
	if (a_sSubjectName != OpcUa_Null && strlen(a_sSubjectName) > 0)
	{
		std::string subjectName = a_sSubjectName;

		int length = strlen(a_sSubjectName);

		int start = 0;
		int end = 0;
		bool nameExtracted = false;
		std::string name;
		std::string value;

		for (int ii = 0; ii < length;)
		{
			// check if the start of name found.
			if (!nameExtracted)
			{
				// skip leading white space.
				while (ii < length && isspace(a_sSubjectName[ii]))
				{
					ii++;
				}

				start = ii;

				// read name.
				while (ii < length && isalpha(a_sSubjectName[ii]))
				{
					ii++;
				}

				end = ii;

				if (end > start)
				{
					name = subjectName.substr(start, end-start);

					// skip trailing white space.
					while (ii < length && isspace(a_sSubjectName[ii]))
					{
						ii++;
					}

					// move past equal.
					if (ii < length && a_sSubjectName[ii] == '=')
					{
						ii++;
					}

					nameExtracted = true;
				}
			}

			else
			{
				// skip leading white space.
				while (ii < length && isspace(a_sSubjectName[ii]))
				{
					ii++;
				}

				bool quoted = false;

				// check for quote.
				if (ii < length && a_sSubjectName[ii] == '"')
				{
					ii++;
					quoted = true;
				}

				start = ii;

				if (quoted)
				{
					// check for end quote.
					while (ii < length && a_sSubjectName[ii] != '"')
					{
						ii++;
					}

					end = ii;

					// skip trailing white space.
					while (ii < length && isspace(a_sSubjectName[ii]))
					{
						ii++;
					}
				}

				// check for end separator.
				while (ii < length && a_sSubjectName[ii] != '/')
				{
					ii++;
				}

				if (!quoted)
				{
					end = ii;
				}

				if (end > start)
				{
					value = subjectName.substr(start, end-start);

					// add the pair to the list.
					fieldNames.push_back(name);
					fieldValues.push_back(value);
					nameExtracted = false;
				}

				ii++;
			}
		}
	}

	// create a default subject name.
	if (fieldNames.size() == 0)
	{
		fieldNames.push_back("CN");
		fieldValues.push_back(a_sApplicationName);

		// ensure organization is present.
		if (a_sOrganization != NULL && strlen(a_sOrganization) > 0)
		{
			fieldNames.push_back("O");
			fieldValues.push_back(a_sOrganization);
		}

		// ensure domain is present.
		if (!a_bIsCA)
		{
			fieldNames.push_back("DC");
			fieldValues.push_back(domainNames[0]);
		}
	}

	// create the provider.
	uStatus = OpcUa_Certificate_CreateCryptoProviders(&tPkiProvider, &tCryptoProvider);
	OpcUa_GotoErrorIfBad(uStatus);

	// set the current date as the start of the validity period.
	tvalidToInSec = 30*24*3600*(OpcUa_Int64)a_uLifetimeInMonths;

	// determine size of public key.
	uStatus = OpcUa_Crypto_GenerateAsymmetricKeypair(
		&tCryptoProvider,
		a_uKeyType,
		a_uKeySize,
		&tPublicKey,
		a_pPrivateKey);

	OpcUa_GotoErrorIfBad(uStatus);

	// allocate public key buffer.
	tPublicKey.Key.Data = (OpcUa_Byte*)OpcUa_Alloc(tPublicKey.Key.Length);
	OpcUa_GotoErrorIfAllocFailed(tPublicKey.Key.Data);

	// determine size of private key.
	uStatus = OpcUa_Crypto_GenerateAsymmetricKeypair(
		&tCryptoProvider,
		a_uKeyType,
		a_uKeySize,
		&tPublicKey,
		a_pPrivateKey);

	OpcUa_GotoErrorIfBad(uStatus);

	// allocate private key buffer.
	a_pPrivateKey->Key.Data = (OpcUa_Byte*)OpcUa_Alloc(a_pPrivateKey->Key.Length);
	OpcUa_GotoErrorIfAllocFailed(a_pPrivateKey->Key.Data);

	// generate a new key pair.
	uStatus = OpcUa_Crypto_GenerateAsymmetricKeypair(
		&tCryptoProvider,
		a_uKeyType,
		a_uKeySize,
		&tPublicKey,
		a_pPrivateKey);

	OpcUa_GotoErrorIfBad(uStatus);

	// create the subject name fields.
	pSubjectNameFields = (OpcUa_Crypto_NameEntry*)OpcUa_Alloc(fieldNames.size()*sizeof(OpcUa_Crypto_NameEntry));
	OpcUa_GotoErrorIfAllocFailed(pSubjectNameFields);
	memset(pSubjectNameFields, 0, fieldNames.size()*sizeof(OpcUa_Crypto_NameEntry));

	// reverse order.
	for (int ii = (int)fieldNames.size()-1; ii >= 0; ii--)
	{
		int index = (int)fieldNames.size()-1-ii;
		pSubjectNameFields[index].key = (char*)fieldNames[ii].c_str();
		pSubjectNameFields[index].value = (char*)fieldValues[ii].c_str();
	}

	pExtensions[0].key = (OpcUa_CharA*)SN_subject_key_identifier;
	pExtensions[0].value = (OpcUa_CharA*)"hash";

	pExtensions[1].key = (OpcUa_CharA*)SN_authority_key_identifier;
	pExtensions[1].value = (OpcUa_CharA*)"keyid, issuer:always";

	if (!a_bIsCA)
	{
		pExtensions[2].key = (OpcUa_CharA*)SN_basic_constraints;
		pExtensions[2].value = (OpcUa_CharA*)"critical, CA:FALSE";

		pExtensions[3].key = (OpcUa_CharA*)SN_key_usage;
		pExtensions[3].value = (OpcUa_CharA*)"critical, nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyCertSign";

		pExtensions[4].key = (OpcUa_CharA*)SN_ext_key_usage;
		pExtensions[4].value = (OpcUa_CharA*)"critical, serverAuth, clientAuth";

		// Add the subject alternate name extension.
		subjectAltName += "URI:";
		subjectAltName += applicationUri;

		for (OpcUa_UInt32 ii = 0; ii < domainNames.size(); ii++)
		{
			std::string domainName = domainNames[ii];

			int iResult = inet_addr(domainName.c_str());

			if (iResult != (int)INADDR_NONE)
			{
				subjectAltName += ",IP:";
			}
			else
			{
				subjectAltName += ",DNS:";
			}

			subjectAltName += domainName;
		}

		pExtensions[5].key = (OpcUa_CharA*)SN_subject_alt_name;
		pExtensions[5].value = (char*)subjectAltName.c_str();
	}
	else
	{
		pExtensions[2].key = (OpcUa_CharA*)SN_basic_constraints;
		pExtensions[2].value = (OpcUa_CharA*)"critical, CA:TRUE";

		pExtensions[3].key = (OpcUa_CharA*)SN_key_usage;
		pExtensions[3].value = (OpcUa_CharA*)"critical, digitalSignature, keyCertSign, cRLSign";
	}

	pPosition = NULL;
	pPrivateKey = a_pPrivateKey;

	// decode the issuer certificate.
	if (a_pIssuerCertificate != NULL && a_pIssuerCertificate->Length > 0)
	{
		pPosition = a_pIssuerCertificate->Data;
		pX509IssuerCertificate = (OpcUa_Certificate*)d2i_X509(NULL, (const unsigned char**)&pPosition, a_pIssuerCertificate->Length);

		if (pX509IssuerCertificate == NULL)
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
		}

		if (a_pIssuerPrivateKey != NULL && a_pIssuerPrivateKey->Key.Length > 0)
		{
			// hack to get around the fact that the load private key and the create key functions use
			// different constants to identify the RS public keys.
			a_pIssuerPrivateKey->Type = OpcUa_Crypto_sha1WithRSAEncryption_Id;

			// use the issuer key for signing.
			pPrivateKey = a_pIssuerPrivateKey;
		}
	}

	// create the certificate.
	uStatus = OpcUa_Crypto_CreateCertificate(
		&tCryptoProvider,
		0,
		tvalidToInSec,
		pSubjectNameFields,
		fieldNames.size(),
		tPublicKey,
		pExtensions,
		(a_bIsCA)?4:6,
		OPCUA_P_SHA_160,
		*pPrivateKey,
		a_pCertificate);

	OpcUa_GotoErrorIfBad(uStatus);

	// save the certificate.
	uStatus = OpcUa_Certificate_SavePrivateKeyInStore(
		a_sStorePath,
		a_eFileFormat,
		a_sPassword,
		a_pCertificate,
		a_pPrivateKey,
		a_pPrivateKeyFilePath);

	OpcUa_GotoErrorIfBad(uStatus);

	// save the public key certificate.
	uStatus = OpcUa_Certificate_SavePublicKeyInStore(
		a_sStorePath,
		a_pCertificate,
		a_pCertificateFilePath);

	OpcUa_GotoErrorIfBad(uStatus);

	// clean up.
	X509_free((X509*)pX509IssuerCertificate);
	OpcUa_Free(pSubjectNameFields);
	OpcUa_Key_Clear(&tPublicKey);
	OpcUa_Certificate_DeleteCryptoProviders(&tPkiProvider, &tCryptoProvider);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pX509IssuerCertificate != NULL)
	{
		X509_free((X509*)pX509IssuerCertificate);
	}

	OpcUa_Free(pSubjectNameFields);
	OpcUa_Key_Clear(a_pPrivateKey);
	OpcUa_ByteString_Clear(a_pCertificate);
	OpcUa_Key_Clear(&tPublicKey);
	OpcUa_Certificate_DeleteCryptoProviders(&tPkiProvider, &tCryptoProvider);

OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_Certificate_GetInfo
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_GetInfo(
	OpcUa_ByteString* a_pCertificate,
	OpcUa_StringA**   a_psNameEntries,
	OpcUa_UInt32*		a_puNoOfNameEntries,
	OpcUa_StringA*	a_psCommonName,
	OpcUa_StringA*	a_psThumbprint,
	OpcUa_StringA*	a_psApplicationUri,
	OpcUa_StringA**   a_psDomains,
	OpcUa_UInt32*		a_puNoOfDomains)
{

	OpcUa_Byte pThumbprint[SHA_DIGEST_LENGTH];
	OpcUa_CharA sBuffer[MAX_PATH*10];
	X509* pCertificate = NULL;
	const unsigned char* pPosition = NULL;
	std::vector<std::string> entries;
	std::string fullName;
	STACK_OF(CONF_VALUE)* subjectAltNameEntries = NULL;
	GENERAL_NAMES* subjectAltName = NULL;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_GetThumbprint");

	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

	// initialize output parameters.
	if (a_psNameEntries != NULL)
	{
		OpcUa_GotoErrorIfArgumentNull(a_puNoOfNameEntries);
		*a_psNameEntries = NULL;
		*a_puNoOfNameEntries = 0;
	}

	if (a_psDomains != NULL)
	{
		OpcUa_GotoErrorIfArgumentNull(a_puNoOfDomains);
		*a_psDomains = NULL;
		*a_puNoOfDomains = 0;
	}

	if (a_psCommonName != NULL)
	{
		*a_psCommonName = NULL;
	}

	if (a_psThumbprint != NULL)
	{
		*a_psThumbprint = NULL;
	}

	if (a_psApplicationUri != NULL)
	{
		*a_psApplicationUri = NULL;
	}

	// initialize local storage.
	OpcUa_MemSet(pThumbprint, 0, SHA_DIGEST_LENGTH);
	OpcUa_MemSet(sBuffer, 0, sizeof(sBuffer));

	// decode the certifcate.
	pPosition = a_pCertificate->Data;
	pCertificate = d2i_X509(NULL, &pPosition, a_pCertificate->Length);

	if (pCertificate == NULL)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	if (a_psThumbprint != NULL)
	{
		// compute the hash.
		SHA1(a_pCertificate->Data, a_pCertificate->Length, pThumbprint);

		// allocate string to return.
		int iLength = (2*SHA_DIGEST_LENGTH+1)*sizeof(OpcUa_CharA);
		*a_psThumbprint = (OpcUa_StringA)OpcUa_Alloc(iLength);
		OpcUa_MemSet(*a_psThumbprint, 0, iLength);

		// convert to a string.
		for (int ii = 0; ii < SHA_DIGEST_LENGTH; ii++)
		{
			sprintf(*a_psThumbprint+ii*2, "%02X", pThumbprint[ii]);
		}
	}

	if (a_psNameEntries != NULL || a_psCommonName != NULL)
	{
		// get the subject name.
		X509_name_st* pName = X509_get_subject_name(pCertificate);

		if (pName == NULL)
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
		}

		X509_NAME_oneline(pName, sBuffer, sizeof(sBuffer));

		// parse the fields.
		fullName = sBuffer;

		int iStart = 0;
		int iEnd = fullName.find_first_of('/');

		do
		{
			if (iEnd == (int)std::string::npos)
			{
				if (iStart < (int)fullName.size())
				{
					entries.push_back(fullName.substr(iStart));
				}

				break;
			}

			if (iEnd > iStart)
			{
				entries.push_back(fullName.substr(iStart, iEnd-iStart));
			}

			iStart = iEnd+1;
			iEnd = fullName.find_first_of('/', iStart);
		}
		while (iStart != (int)std::string::npos);

		// extract the name entries.
		if (a_psNameEntries != NULL)
		{
			uStatus = OpcUa_Certificate_CopyStrings(entries, a_psNameEntries, a_puNoOfNameEntries);
			OpcUa_GotoErrorIfBad(uStatus);
		}

		// extract the common name.
		if (a_psCommonName != NULL)
		{
			for (unsigned int ii = 0; ii < entries.size(); ii++)
			{
				std::string entry(entries[ii]);

				if (entry.find("CN=") == 0)
				{
					int iLength = entry.size()+1;
					*a_psCommonName = (OpcUa_StringA)OpcUa_Alloc(iLength);
					OpcUa_GotoErrorIfAllocFailed(*a_psCommonName);
					strcpy(*a_psCommonName, entry.substr(3).c_str());
					break;
				}
			}
		}
	}

	if (a_psApplicationUri != NULL || a_psDomains != NULL)
	{
		// find the subject alt name extension.
		STACK_OF(X509_EXTENSION)* pExtensions = pCertificate->cert_info->extensions;

		for (int ii = 0; ii < sk_X509_EXTENSION_num(pExtensions); ii++)
		{
			X509_EXTENSION* pExtension = sk_X509_EXTENSION_value(pExtensions, ii);

			// get the internal id for the extension.
			int nid = OBJ_obj2nid(pExtension->object);

			if (nid == 0)
			{
				// check for obsolete name.
				ASN1_OBJECT* oid = (ASN1_OBJECT*)pExtension->object;

				if (memcmp(oid->data, ::OID_SUBJECT_ALT_NAME, 3) == 0)
				{
					oid->nid = nid = NID_subject_alt_name;
				}
			}

			if (nid == NID_subject_alt_name)
			{
				subjectAltName = (GENERAL_NAMES*)X509V3_EXT_d2i(pExtension);
			}
		}

		// extract the fields from the subject alt name extension.
		if (subjectAltName != NULL)
		{
			entries.clear();
			subjectAltNameEntries = i2v_GENERAL_NAMES(NULL, subjectAltName, NULL);

			for (int ii = 0; ii < sk_CONF_VALUE_num(subjectAltNameEntries); ii++)
			{
				CONF_VALUE* conf = sk_CONF_VALUE_value(subjectAltNameEntries, ii);

				if (conf == NULL)
				{
					continue;
				}

				// check for URI.
				if (a_psApplicationUri != NULL)
				{
					// copy the application uri.
					if (*a_psApplicationUri == NULL && strcmp(conf->name, "URI") == 0)
					{
						int iLength = strlen(conf->value)+1;
						*a_psApplicationUri = (OpcUa_StringA)OpcUa_Alloc(iLength);
						OpcUa_GotoErrorIfAllocFailed(*a_psApplicationUri);
						strcpy(*a_psApplicationUri, conf->value);
					}
				}

				// check for domain.
				if (a_psDomains != NULL)
				{
					if (strcmp(conf->name, "DNS") == 0)
					{
						entries.push_back(conf->value);
					}

					if (strcmp(conf->name, "IP Address") == 0)
					{
						entries.push_back(conf->value);
					}
				}
			}

			sk_CONF_VALUE_pop_free(subjectAltNameEntries, X509V3_conf_free);
			subjectAltNameEntries = NULL;

			sk_GENERAL_NAME_pop_free(subjectAltName, GENERAL_NAME_free);
			subjectAltName = NULL;

			// copy domains.
			if (a_psDomains != NULL)
			{
				uStatus = OpcUa_Certificate_CopyStrings(entries, a_psDomains, a_puNoOfDomains);
				OpcUa_GotoErrorIfBad(uStatus);
			}
		}
	}

	X509_free(pCertificate);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pCertificate != NULL)
	{
		X509_free(pCertificate);
	}

	if (subjectAltNameEntries != NULL)
	{
		sk_CONF_VALUE_pop_free(subjectAltNameEntries, X509V3_conf_free);
	}

	if (subjectAltName != NULL)
	{
		sk_GENERAL_NAME_pop_free(subjectAltName, GENERAL_NAME_free);
	}

	if (a_psNameEntries != NULL && *a_psNameEntries != NULL)
	{
		for (unsigned int ii = 0; ii < *a_puNoOfNameEntries; ii++)
		{
			OpcUa_Free((*a_psNameEntries)[ii]);
		}

		OpcUa_Free(*a_psNameEntries);
		*a_psNameEntries = NULL;
	}

	if (a_psCommonName != NULL && *a_psCommonName != NULL)
	{
		OpcUa_Free(*a_psCommonName);
		*a_psCommonName = NULL;
	}

	if (a_psThumbprint != NULL && *a_psThumbprint != NULL)
	{
		OpcUa_Free(*a_psThumbprint);
		*a_psThumbprint = NULL;
	}

	if (a_psApplicationUri != NULL && *a_psApplicationUri != NULL)
	{
		OpcUa_Free(*a_psApplicationUri);
		*a_psApplicationUri = NULL;
	}

	if (a_psDomains != NULL && *a_psDomains != NULL)
	{
		for (unsigned int ii = 0; ii < *a_puNoOfDomains; ii++)
		{
			OpcUa_Free((*a_psDomains)[ii]);
		}

		OpcUa_Free(*a_psDomains);
		*a_psDomains = NULL;
	}

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_GetThumbprint
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_GetThumbprint(
	OpcUa_ByteString* a_pCertificate,
	OpcUa_StringA*	a_pThumbprint)
{
	return OpcUa_Certificate_GetInfo(a_pCertificate, NULL, NULL, NULL, a_pThumbprint, NULL, NULL, NULL);
}

/*============================================================================
 * OpcUa_Certificate_GetCommonName
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_GetCommonName(
	OpcUa_ByteString* a_pCertificate,
	OpcUa_StringA*	m_pCommonName)
{
	return OpcUa_Certificate_GetInfo(a_pCertificate, NULL, NULL, m_pCommonName, NULL, NULL, NULL, NULL);
}

/*============================================================================
 * OpcUa_Certificate_SavePublicKeyInStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_SavePublicKeyInStore(
	OpcUa_StringA		a_sStorePath,
	OpcUa_ByteString* a_pCertificate,
	OpcUa_StringA*	a_pFilePath)
{
	BIO* pPublicKeyFile = OpcUa_Null;
	std::string filePath;
	int iResult = 0;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_SavePublicKeyInStore");

	OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

	if (a_pFilePath != NULL) *a_pFilePath = NULL;

	// get the file name for the certificate.
	filePath = OpcUa_Certificate_GetFilePathForCertificate(
		a_sStorePath,
		a_pCertificate,
		OpcUa_Crypto_Encoding_DER,
		OpcUa_True);

	if (filePath.empty())
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
	}

	pPublicKeyFile = BIO_new_file((const char*)filePath.c_str(), "wb");
	OpcUa_ReturnErrorIfArgumentNull(pPublicKeyFile);

	iResult = BIO_write(pPublicKeyFile, a_pCertificate->Data, a_pCertificate->Length);

	if (iResult == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	// return the file path.
	if (a_pFilePath != NULL)
	{
		*a_pFilePath = (OpcUa_StringA)OpcUa_Alloc(filePath.size()+1);
		OpcUa_GotoErrorIfAllocFailed(*a_pFilePath);
		strcpy(*a_pFilePath, filePath.c_str());
	}

	BIO_free(pPublicKeyFile);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pPublicKeyFile != NULL)
	{
		BIO_free(pPublicKeyFile);
	}

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_SavePrivateKeyInStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_SavePrivateKeyInStore(
	OpcUa_StringA		a_sStorePath,
	OpcUa_P_FileFormat a_eFileFormat,
	OpcUa_StringA		a_sPassword,
	OpcUa_ByteString*  a_pCertificate,
	OpcUa_Key*			a_pPrivateKey,
	OpcUa_StringA*		a_pFilePath)
{
	BIO*		pPrivateKeyFile		= OpcUa_Null;
	RSA*		pRsaPrivateKey		= OpcUa_Null;
	EVP_PKEY* pEvpKey				= OpcUa_Null;
	X509*		pX509Certificate	= OpcUa_Null;
	const unsigned char* pPos		= OpcUa_Null;

	std::string filePath;
	OpcUa_StringA sCommonName = OpcUa_Null;
	OpcUa_Byte* pPosition = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_SavePrivateKeyInStore");

	OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

	if (a_pFilePath != NULL) *a_pFilePath = NULL;

	// check for supported format.
	if (a_eFileFormat == OpcUa_Crypto_Encoding_Invalid)
	{
		return OpcUa_BadInvalidArgument;
	}

	// check for supported key type.
	if (a_pPrivateKey->Type != OpcUa_Crypto_sha1WithRSAEncryption_Id
			&& a_pPrivateKey->Type != OpcUa_Crypto_KeyType_Rsa_Private)
	{
		return OpcUa_BadInvalidArgument;
	}

	// get the file name for the certificate.
	filePath = OpcUa_Certificate_GetFilePathForCertificate(
		a_sStorePath,
		a_pCertificate,
		a_eFileFormat,
		OpcUa_True);

	if (filePath.empty())
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
	}

	pPrivateKeyFile = BIO_new_file((const char*)filePath.c_str(), "wb");
	OpcUa_GotoErrorIfNull(pPrivateKeyFile, OpcUa_BadEncodingError);

	// convert DER encoded data to RSA data.
	pPos = a_pPrivateKey->Key.Data;
	pRsaPrivateKey = d2i_RSAPrivateKey(NULL, &pPos, a_pPrivateKey->Key.Length);
	OpcUa_GotoErrorIfAllocFailed(pRsaPrivateKey);

	pEvpKey = EVP_PKEY_new();

	// convert to intermediary openssl struct
	if (!EVP_PKEY_set1_RSA(pEvpKey, pRsaPrivateKey))
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	// convert public key to X509 structure.
	pPosition = a_pCertificate->Data;
	pX509Certificate = d2i_X509((X509**)OpcUa_Null, (const unsigned char**)&pPosition, a_pCertificate->Length);
	OpcUa_GotoErrorIfNull(pX509Certificate, OpcUa_Bad);

	switch(a_eFileFormat)
	{
		case OpcUa_Crypto_Encoding_PEM:
		{
			// select encryption algorithm.
			const EVP_CIPHER* pCipher = NULL;
			char* pPassword = NULL;

			if (a_sPassword != NULL)
			{
				pCipher = EVP_des_ede3_cbc();
				pPassword = a_sPassword;
			}

			// write to file.
			int iResult = PEM_write_bio_PrivateKey(
				pPrivateKeyFile,
				pEvpKey,
				pCipher,
				NULL,
				0,
				0,
				pPassword);

			if (iResult == 0)
			{
				OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
			}

			break;
		}

		case OpcUa_Crypto_Encoding_PKCS12:
		{
			// use the common name as the friendly name.
			uStatus = OpcUa_Certificate_GetCommonName(a_pCertificate, &sCommonName);
			OpcUa_GotoErrorIfBad(uStatus);

			// create certificate.
			PKCS12* pPkcs12 = PKCS12_create(
				a_sPassword,
				sCommonName,
				pEvpKey,
				pX509Certificate,
				0,
				0,
				0,
				0,
				0,
				0);

			OpcUa_GotoErrorIfNull(pPkcs12, OpcUa_Bad);

			// write to file.
			int iResult = i2d_PKCS12_bio(pPrivateKeyFile, pPkcs12);

			// free certificate.
			PKCS12_free(pPkcs12);

			if (iResult == 0)
			{
				OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
			}

			break;
		}

		case OpcUa_Crypto_Encoding_DER:
		default:
		{
			uStatus = OpcUa_BadNotSupported;
			OpcUa_GotoError;
		}
	}

	// return the file path.
	if (a_pFilePath != NULL)
	{
		*a_pFilePath = (OpcUa_StringA)OpcUa_Alloc(filePath.size()+1);
		OpcUa_GotoErrorIfAllocFailed(*a_pFilePath);
		strcpy(*a_pFilePath, filePath.c_str());
	}

	// free memory.
	EVP_PKEY_free(pEvpKey);
	RSA_free(pRsaPrivateKey);
	BIO_free(pPrivateKeyFile);
	X509_free(pX509Certificate);
	OpcUa_Free(sCommonName);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pPrivateKeyFile != NULL)
	{
		BIO_free(pPrivateKeyFile);
	}

	if (pEvpKey != NULL)
	{
		EVP_PKEY_free(pEvpKey);
	}

	if (pRsaPrivateKey != NULL)
	{
		RSA_free(pRsaPrivateKey);
	}

	if (pX509Certificate != NULL)
	{
		X509_free(pX509Certificate);
	}

	if (sCommonName != NULL)
	{
		OpcUa_Free(sCommonName);
	}

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_LoadPrivateKeyFromFile
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LoadPrivateKeyFromFile(
	OpcUa_StringA		a_sFilePath,
	OpcUa_P_FileFormat a_eFileFormat,
	OpcUa_StringA		a_sPassword,
	OpcUa_ByteString*  a_pCertificate,
	OpcUa_Key*			a_pPrivateKey)
{
	BIO*		pPrivateKeyFile = OpcUa_Null;
	RSA*		pRsaPrivateKey = OpcUa_Null;
	EVP_PKEY* pEvpKey = OpcUa_Null;
	PKCS12*   pPkcs12 = OpcUa_Null;
	X509*		pX509 = OpcUa_Null;

	int iResult = 0;
	OpcUa_Byte* pPosition = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_LoadPrivateKeyFromFile");

	OpcUa_ReturnErrorIfArgumentNull(a_sFilePath);
	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

	OpcUa_ByteString_Initialize(a_pCertificate);
	OpcUa_Key_Initialize(a_pPrivateKey);

	// check for supported format.
	if (a_eFileFormat == OpcUa_Crypto_Encoding_Invalid)
	{
		return OpcUa_BadInvalidArgument;
	}

	pPrivateKeyFile = BIO_new_file(a_sFilePath, "rb");
	OpcUa_GotoErrorIfNull(pPrivateKeyFile, OpcUa_BadEncodingError);

	switch(a_eFileFormat)
	{
		case OpcUa_Crypto_Encoding_PEM:
		{
			// read from file.
			pEvpKey = PEM_read_bio_PrivateKey(
				pPrivateKeyFile,
				NULL,
				0,
				a_sPassword);

			OpcUa_GotoErrorIfNull(pEvpKey, OpcUa_Bad);
			break;
		}

		case OpcUa_Crypto_Encoding_PKCS12:
		{
			// read from file.
			PKCS12* pPkcs12 = d2i_PKCS12_bio(pPrivateKeyFile, NULL);

			if (pPkcs12 == 0)
			{
				OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
			}

			// parse the certificate.
			iResult = PKCS12_parse(pPkcs12, a_sPassword, &pEvpKey, &pX509, NULL);

			if (iResult == 0)
			{
				OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
			}

			// free certificate.
			PKCS12_free(pPkcs12);
			pPkcs12 = NULL;
			break;
		}

		case OpcUa_Crypto_Encoding_DER:
		default:
		{
			uStatus = OpcUa_BadNotSupported;
			OpcUa_GotoError;
		}
	}

	// get the certificate embedded with the private key.
	if (pX509 != NULL)
	{
		// need to convert to DER encoded certificate.
		a_pCertificate->Length = i2d_X509((X509*)pX509, NULL);

		if (a_pCertificate->Length <= 0)
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
		}

		a_pCertificate->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pCertificate->Length);
		OpcUa_GotoErrorIfAllocFailed(a_pCertificate->Data);

		// OpenSSL likes to modify input parameters.
		OpcUa_Byte* pPosition = a_pCertificate->Data;
		int iResult = i2d_X509((X509*)pX509, &pPosition);

		if (iResult <= 0)
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
		}

		X509_free((X509*)pX509);
		pX509 = NULL;
	}

	// get the private key.
	pRsaPrivateKey = EVP_PKEY_get1_RSA(pEvpKey);
	OpcUa_GotoErrorIfNull(pRsaPrivateKey, OpcUa_Bad);

	// convert DER encoded data to RSA data.
	a_pPrivateKey->Type = OpcUa_Crypto_KeyType_Rsa_Private;
	a_pPrivateKey->Key.Length = i2d_RSAPrivateKey(pRsaPrivateKey, NULL);

	if (a_pPrivateKey->Key.Length <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	// allocate key.
	a_pPrivateKey->Key.Data = (OpcUa_Byte*)OpcUa_Alloc(a_pPrivateKey->Key.Length);
	OpcUa_GotoErrorIfAllocFailed(a_pPrivateKey->Key.Data);
	memset(a_pPrivateKey->Key.Data, 0, a_pPrivateKey->Key.Length);

	pPosition = a_pPrivateKey->Key.Data;
	iResult = i2d_RSAPrivateKey(pRsaPrivateKey, &pPosition);

	if (iResult <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	// free memory.
	EVP_PKEY_free(pEvpKey);
	RSA_free(pRsaPrivateKey);
	BIO_free(pPrivateKeyFile);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_ByteString_Clear(a_pCertificate);
	OpcUa_Key_Clear(a_pPrivateKey);

	if (pPrivateKeyFile != NULL)
	{
		BIO_free(pPrivateKeyFile);
	}

	if (pEvpKey != NULL)
	{
		EVP_PKEY_free(pEvpKey);
	}

	if (pX509 != NULL)
	{
		X509_free((X509*)pX509);
	}

	if (pRsaPrivateKey != NULL)
	{
		RSA_free(pRsaPrivateKey);
	}

	if (pPkcs12 != NULL)
	{
		PKCS12_free(pPkcs12);
	}

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_LoadPrivateKeyFromStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LoadPrivateKeyFromStore(
	OpcUa_StringA		a_sStorePath,
	OpcUa_P_FileFormat a_eFileFormat,
	OpcUa_StringA		a_sPassword,
	OpcUa_ByteString*  a_pCertificate,
	OpcUa_Key*			a_pPrivateKey)
{
	std::string filePath;
	OpcUa_ByteString tCertificate;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_LoadPrivateKeyFromStore");

	OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

	OpcUa_ByteString_Initialize(&tCertificate);
	OpcUa_Key_Initialize(a_pPrivateKey);

	// check for supported format.
	if (a_eFileFormat == OpcUa_Crypto_Encoding_Invalid)
	{
		return OpcUa_BadInvalidArgument;
	}

	// get the file name for the certificate.
	filePath = OpcUa_Certificate_GetFilePathForCertificate(
		a_sStorePath,
		a_pCertificate,
		a_eFileFormat,
		OpcUa_False);

	if (filePath.empty())
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
	}

	// load from file.
	uStatus = OpcUa_Certificate_LoadPrivateKeyFromFile(
		(OpcUa_StringA)filePath.c_str(),
		a_eFileFormat,
		a_sPassword,
		&tCertificate,
		a_pPrivateKey);

	OpcUa_GotoErrorIfBad(uStatus);
	OpcUa_ByteString_Clear(&tCertificate);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_ByteString_Clear(&tCertificate);
	OpcUa_Key_Clear(a_pPrivateKey);

OpcUa_FinishErrorHandling;
}

///*============================================================================
// * OpcUa_Certificate_FindContext
// *===========================================================================*/
//struct OpcUa_Certificate_FindContext
//{
//	HCERTSTORE Store;
//	HANDLE File;
//	PCCERT_CONTEXT Context;
//};

/*============================================================================
 * OpcUa_Certificate_CheckForMatch
 *===========================================================================*/
bool OpcUa_Certificate_CheckForMatch(
	OpcUa_ByteString* a_pCertificate,
	OpcUa_StringA		a_sCommonName,
	OpcUa_StringA		a_sThumbprint)
{
	bool match = true;
	OpcUa_StringA sMatchString = NULL;

	// check for a match on the thumbprint.
	if (a_sThumbprint != NULL && strlen(a_sThumbprint) > 0)
	{
		OpcUa_StatusCode uStatus = OpcUa_Certificate_GetThumbprint(a_pCertificate, &sMatchString);

		if (OpcUa_IsBad(uStatus))
		{
			return false;
		}

		if (strcasecmp(sMatchString, a_sThumbprint) != 0)
		{
			match = false;
		}

		OpcUa_Free(sMatchString);
		sMatchString = NULL;
	}

	// check for a match on the common name.
	if (match && a_sCommonName != NULL && strlen(a_sCommonName) > 0)
	{
		OpcUa_StatusCode uStatus = OpcUa_Certificate_GetCommonName(a_pCertificate, &sMatchString);

		if (OpcUa_IsBad(uStatus))
		{
			return false;
		}

		if (strcasecmp(sMatchString, a_sCommonName) != 0)
		{
			match = false;
		}

		OpcUa_Free(sMatchString);
		sMatchString = NULL;
	}

	return match;
}

///*============================================================================
// * OpcUa_Certificate_FindCertificateInWindowsStore
// *===========================================================================*/
//OpcUa_StatusCode OpcUa_Certificate_FindCertificateInWindowsStore(
//	OpcUa_Handle*		a_pContext,
//	OpcUa_Boolean		a_bUseMachineStore,
//	OpcUa_StringA		a_sStoreName,
//	OpcUa_StringA		a_sCommonName,
//	OpcUa_StringA		a_sThumbprint,
//	OpcUa_ByteString* a_pCertificate)
//{
//	//OpcUa_Char* wszStoreName = NULL;
//	//OpcUa_Certificate_FindContext* pContext = NULL;
//
//OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_FindCertificateInWindowsStore");
//
//	OpcUa_ReturnErrorIfArgumentNull(a_pContext);
//	OpcUa_ReturnErrorIfArgumentNull(a_sStoreName);
//	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
//
//	OpcUa_ByteString_Initialize(a_pCertificate);
//
//	if (*a_pContext != NULL)
//	{
//		pContext = (OpcUa_Certificate_FindContext*)*a_pContext;
//	}
//
//	// create a new context.
//	if (pContext == NULL)
//	{
//		uStatus = OpcUa_StringToUnicode(a_sStoreName, (OpcUa_Char**)&wszStoreName);
//		OpcUa_GotoErrorIfBad(uStatus);
//
//		pContext = new OpcUa_Certificate_FindContext();
//
//		// open the certificate store.
//		OpcUa_UInt32 dwFlags = 0;
//
//		if (a_bUseMachineStore)
//		{
//			dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
//		}
//		else
//		{
//			dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;
//		}
//
//		// open the store.
//		pContext->Store = CertOpenStore(
//			CERT_STORE_PROV_SYSTEM,
//			0,
//			0,
//			dwFlags,
//			wszStoreName);
//
//		if (pContext->Store == 0)
//		{
//			OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//		}
//
//		OpcUa_Free(wszStoreName);
//	}
//
//	// Find the certificates in the system store.
//	while (pContext->Context = CertEnumCertificatesInStore(pContext->Store, pContext->Context))
//	{
//		OpcUa_ByteString tCertificate;
//		tCertificate.Data = pContext->Context->pbCertEncoded;
//		tCertificate.Length = pContext->Context->cbCertEncoded;
//
//		// check for match.
//		bool match = OpcUa_Certificate_CheckForMatch(&tCertificate, a_sCommonName, a_sThumbprint);
//
//		// copy certificate if match found.
//		if (match)
//		{
//			a_pCertificate->Data = (OpcUa_Byte*)OpcUa_Alloc(tCertificate.Length);
//			OpcUa_GotoErrorIfAllocFailed(a_pCertificate->Data);
//			OpcUa_MemCpy(a_pCertificate->Data, tCertificate.Length, tCertificate.Data, tCertificate.Length);
//			a_pCertificate->Length = tCertificate.Length;
//			break;
//		}
//	}
//
//	// check if nothing found.
//	if (pContext->Context == NULL)
//	{
//		CertCloseStore(pContext->Store, 0);
//		delete pContext;
//		*a_pContext = NULL;
//	}
//
//OpcUa_ReturnStatusCode;
//OpcUa_BeginErrorHandling;
//
//	OpcUa_ByteString_Clear(a_pCertificate);
//	OpcUa_Certificate_FreeFindContext((OpcUa_Handle*)&pContext);
//
//	if (wszStoreName != NULL)
//	{
//		OpcUa_Free(wszStoreName);
//	}
//
//OpcUa_FinishErrorHandling;
//}

/*============================================================================
 * OpcUa_Certificate_FindCertificateInStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_FindCertificateInStore(
	OpcUa_Handle*		a_pContext,
	OpcUa_StringA		a_sStorePath,
	OpcUa_Boolean		a_sHasPrivateKey,
	OpcUa_StringA		a_sPassword,
	OpcUa_StringA		a_sCommonName,
	OpcUa_StringA		a_sThumbprint,
	OpcUa_ByteString* a_pCertificate,
	OpcUa_Key*		a_pPrivateKey)
{
	//OpcUa_Certificate_FindContext* pContext = NULL;
	//WIN32_FIND_DATA tFindFileData;
	std::string filePath;
	bool match = false;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_FindCertificateInStore");

	OpcUa_ReturnErrorIfArgumentNull(a_pContext);
	OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

	OpcUa_ByteString_Initialize(a_pCertificate);
	OpcUa_Key_Initialize(a_pPrivateKey);

	filePath = a_sStorePath;
	if (a_sHasPrivateKey)
	{	// search private keys
		filePath += "/private/";
		DIR *dp;
		struct dirent *dirp;
		if ((dp  = opendir(filePath.c_str())) == NULL)
		{
			OpcUa_GotoError;
		}

		while ((dirp = readdir(dp)) != NULL)
		{
			std::string name = dirp->d_name;
			if (name.rfind(".pfx") == name.length() - 4)
				if (name.find(a_sCommonName) != std::string::npos)
				{
					filePath += name;

					uStatus = OpcUa_Certificate_LoadPrivateKeyFromFile(
						(OpcUa_StringA)filePath.c_str(),
						OpcUa_Crypto_Encoding_PKCS12,
						a_sPassword,
						a_pCertificate,
						a_pPrivateKey);

					if (OpcUa_IsBad(uStatus))
					{
						continue;
					}

					match = OpcUa_Certificate_CheckForMatch(a_pCertificate, a_sCommonName, a_sThumbprint);
					if (!match)
					{
						continue;
					}

					// ok, found one
					break;
				}
		}
		closedir(dp);
	}
	else
	{	// serch certificates
		filePath += "/certs/";
		DIR *dp;
		struct dirent *dirp;
		if ((dp  = opendir(filePath.c_str())) == NULL)
		{
			OpcUa_GotoError;
		}

		while ((dirp = readdir(dp)) != NULL)
		{
			std::string name = dirp->d_name;
			if (name.rfind(".der") == name.length() - 4)
				if (name.find(a_sCommonName) != std::string::npos)
				{
					filePath += name;

					uStatus = OpcUa_ReadFile((OpcUa_StringA)filePath.c_str(), a_pCertificate);

					if (OpcUa_IsBad(uStatus))
					{
						continue;
					}

					match = OpcUa_Certificate_CheckForMatch(a_pCertificate, a_sCommonName, a_sThumbprint);
					if (match)
						break;	// ok, found one
				}
		}
		closedir(dp);
	}

	if (!match)
	{
		OpcUa_ByteString_Clear(a_pCertificate);
		OpcUa_Key_Clear(a_pPrivateKey);
	}

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_ByteString_Clear(a_pCertificate);
	OpcUa_Key_Clear(a_pPrivateKey);

OpcUa_FinishErrorHandling;
}

///*============================================================================
// * OpcUa_Certificate_FreeFindContext
// *===========================================================================*/
//OpcUa_StatusCode OpcUa_Certificate_FreeFindContext(
//	OpcUa_Handle* a_pContext)
//{
//	OpcUa_Certificate_FindContext* pContext = NULL;
//
//OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_FreeFindContext");
//
//	OpcUa_ReturnErrorIfArgumentNull(a_pContext);
//
//	if (*a_pContext != NULL)
//	{
//		pContext = (OpcUa_Certificate_FindContext*)*a_pContext;
//	}
//
//	if (pContext != NULL)
//	{
//		if (pContext->Context != NULL)
//		{
//			CertFreeCertificateContext(pContext->Context);
//		}
//
//		if (pContext->Store != NULL)
//		{
//			CertCloseStore(pContext->Store, 0);
//		}
//
//		if (pContext->File != NULL)
//		{
//			FindClose(pContext->File);
//		}
//
//		delete pContext;
//	}
//
//	*a_pContext = NULL;
//
//OpcUa_ReturnStatusCode;
//OpcUa_BeginErrorHandling;
//
//	// nothing to do.
//
//OpcUa_FinishErrorHandling;
//}

///*============================================================================
// * OpcUa_Certificate_ExportPrivateKeyFromWindowsStore
// *===========================================================================*/
//OpcUa_StatusCode OpcUa_Certificate_ExportPrivateKeyFromWindowsStore(
//	OpcUa_Boolean		a_bUseMachineStore,
//	OpcUa_StringA		a_sStoreName,
//	OpcUa_ByteString* a_pCertificate,
//	OpcUa_StringA		a_sPassword,
//	OpcUa_StringA		a_sTargetStorePath,
//	OpcUa_Key*		a_pPrivateKey)
//{
//	HCERTSTORE hMemoryStore = NULL;
//	HCERTSTORE hCertificateStore = NULL;
//	PCCERT_CONTEXT pCertContext = NULL;
//	PCCERT_CONTEXT pCertContext2 = NULL;
//	LPWSTR wszStoreName = NULL;
//	LPWSTR wszPassword = NULL;
//	std::string privateKeyFile;
//	OpcUa_UInt32 dwFlags = 0;
//	BOOL bResult = FALSE;
//
//	CRYPT_HASH_BLOB tThumbprint;
//	CRYPT_DATA_BLOB tPfxData;
//	OpcUa_Byte pHashBuffer[SHA_DIGEST_LENGTH];
//
//OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_ExportPrivateKeyFromWindowsStore");
//
//	OpcUa_ReturnErrorIfArgumentNull(a_sStoreName);
//	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
//	OpcUa_ReturnErrorIfArgumentNull(a_sTargetStorePath);
//	OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);
//
//	memset(&tThumbprint, 0, sizeof(tThumbprint));
//	memset(&tPfxData, 0, sizeof(tPfxData));
//	memset(&pHashBuffer, 0, sizeof(pHashBuffer));
//	OpcUa_Key_Initialize(a_pPrivateKey);
//
//	// open the certificate store.
//	if (a_bUseMachineStore)
//	{
//		dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
//	}
//	else
//	{
//		dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;
//	}
//
//	uStatus = OpcUa_StringToUnicode(a_sStoreName, (OpcUa_Char**)&wszStoreName);
//	OpcUa_GotoErrorIfBad(uStatus);
//
//	// open the store.
//	hCertificateStore = CertOpenStore(
//		CERT_STORE_PROV_SYSTEM,
//		0,
//		0,
//		dwFlags,
//		wszStoreName);
//
//	if (hCertificateStore == 0)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//	}
//
//	// compute the hash.
//	SHA1(a_pCertificate->Data, a_pCertificate->Length, pHashBuffer);
//
//	tThumbprint.pbData = pHashBuffer;
//	tThumbprint.cbData = SHA_DIGEST_LENGTH;
//
//	// find the certificate with the specified hash.
//	pCertContext = CertFindCertificateInStore(
//		hCertificateStore,
//		X509_ASN_ENCODING,
//		0,
//		CERT_FIND_HASH,
//		&tThumbprint,
//		NULL);
//
//	if (pCertContext == NULL)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadNotFound);
//	}
//
//	// create memory store.
//	hMemoryStore = CertOpenStore(
//		CERT_STORE_PROV_MEMORY,
//		0,
//		0,
//		0,
//		OpcUa_Null);
//
//	if (hMemoryStore == NULL)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadNotFound);
//	}
//
//	// create a link to the original certificate.
//	bResult = CertAddCertificateLinkToStore(
//		hMemoryStore,
//		pCertContext,
//		CERT_STORE_ADD_REPLACE_EXISTING,
//		&pCertContext2);
//
//	if (!bResult)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//	}
//
//	// convert the password to unicode.
//	if (a_sPassword != NULL)
//	{
//		uStatus = OpcUa_StringToUnicode(a_sPassword, (OpcUa_Char**)&wszPassword);
//		OpcUa_GotoErrorIfBad(uStatus);
//	}
//
//	// determine the size of the blob.
//	bResult = PFXExportCertStoreEx(
//		hMemoryStore,
//		&tPfxData,
//		wszPassword,
//		0,
//		EXPORT_PRIVATE_KEYS);
//
//	if (!bResult)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//	}
//
//	// allocate memory.
//	tPfxData.pbData = (OpcUa_Byte*)OpcUa_Alloc(tPfxData.cbData);
//	OpcUa_GotoErrorIfAllocFailed(tPfxData.pbData);
//	memset(tPfxData.pbData, 0, tPfxData.cbData);
//
//	// export the PFX blob.
//	bResult = PFXExportCertStoreEx(
//		hMemoryStore,
//		&tPfxData,
//		wszPassword,
//		0,
//		EXPORT_PRIVATE_KEYS);
//
//	if (!bResult)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//	}
//
//	// get the file name for the certificate.
//	privateKeyFile = OpcUa_Certificate_GetFilePathForCertificate(
//		a_sTargetStorePath,
//		a_pCertificate,
//		OpcUa_Crypto_Encoding_PKCS12,
//		OpcUa_True);
//
//	if (privateKeyFile.empty())
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//	}
//
//	// write to the file.
//	uStatus = OpcUa_WriteFile((OpcUa_StringA)privateKeyFile.c_str(), tPfxData.pbData, tPfxData.cbData);
//	OpcUa_GotoErrorIfBad(uStatus);
//
//	// load the certificate that was just saved.
//	uStatus = OpcUa_Certificate_LoadPrivateKeyFromStore(
//		a_sTargetStorePath,
//		OpcUa_Crypto_Encoding_PKCS12,
//		a_sPassword,
//		a_pCertificate,
//		a_pPrivateKey);
//
//	OpcUa_GotoErrorIfBad(uStatus);
//
//	// clean up.
//	CertCloseStore(hMemoryStore, 0);
//	CertCloseStore(hCertificateStore, 0);
//	OpcUa_Free(tPfxData.pbData);
//	OpcUa_Free(wszStoreName);
//	OpcUa_Free(wszPassword);
//
//OpcUa_ReturnStatusCode;
//OpcUa_BeginErrorHandling;
//
//	if (pCertContext != NULL)
//	{
//		CertFreeCertificateContext(pCertContext);
//	}
//
//	if (pCertContext2 != NULL)
//	{
//		CertFreeCertificateContext(pCertContext2);
//	}
//
//	if (hMemoryStore != NULL)
//	{
//		CertCloseStore(hMemoryStore, 0);
//	}
//
//	if (hCertificateStore != NULL)
//	{
//		CertCloseStore(hCertificateStore, 0);
//	}
//
//	OpcUa_Key_Clear(a_pPrivateKey);
//	OpcUa_Free(tPfxData.pbData);
//	OpcUa_Free(wszStoreName);
//	OpcUa_Free(wszPassword);
//
//OpcUa_FinishErrorHandling;
//}
//
///*============================================================================
// * OpcUa_Certificate_ImportToWindowsStore
// *===========================================================================*/
//OpcUa_StatusCode OpcUa_Certificate_ImportToWindowsStore(
//	OpcUa_ByteString* a_pCertificate,
//	OpcUa_Boolean		a_bUseMachineStore,
//	OpcUa_StringA		a_sStoreName)
//{
//	HCERTSTORE hCertificateStore = NULL;
//	LPWSTR wszStoreName = NULL;
//	OpcUa_UInt32 dwFlags = CERT_STORE_OPEN_EXISTING_FLAG;
//	BOOL bResult = FALSE;
//
//OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_ImportToWindowsStore");
//
//	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
//
//	// import certificate.
//	if (a_bUseMachineStore)
//	{
//		dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
//	}
//	else
//	{
//		dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;
//	}
//
//	uStatus = OpcUa_StringToUnicode(a_sStoreName, (OpcUa_Char**)&wszStoreName);
//	OpcUa_GotoErrorIfBad(uStatus);
//
//	// open the store.
//	hCertificateStore = CertOpenStore(
//		CERT_STORE_PROV_SYSTEM,
//		0,
//		0,
//		dwFlags,
//		wszStoreName);
//
//	if (hCertificateStore == 0)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//	}
//
//	// add certificate to store.
//	bResult = CertAddEncodedCertificateToStore(
//		hCertificateStore,
//		X509_ASN_ENCODING,
//		a_pCertificate->Data,
//		a_pCertificate->Length,
//		CERT_STORE_ADD_REPLACE_EXISTING,
//		NULL);
//
//	if (!bResult)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
//	}
//
//	// clean up.
//	CertCloseStore(hCertificateStore, 0);
//	OpcUa_Free(wszStoreName);
//
//OpcUa_ReturnStatusCode;
//OpcUa_BeginErrorHandling;
//
//	if (hCertificateStore != NULL)
//	{
//		CertCloseStore(hCertificateStore, 0);
//	}
//
//	OpcUa_Free(wszStoreName);
//
//OpcUa_FinishErrorHandling;
//}
//
///*============================================================================
// * OpcUa_Certificate_ImportPrivateKeyToWindowsStore
// *===========================================================================*/
//OpcUa_StatusCode OpcUa_Certificate_ImportPrivateKeyToWindowsStore(
//	OpcUa_StringA		a_sSourceStorePath,
//	OpcUa_ByteString* a_pCertificate,
//	OpcUa_StringA		a_sPassword,
//	OpcUa_Boolean		a_bUseMachineStore,
//	OpcUa_StringA		a_sStoreName)
//{
//	HCERTSTORE hFileStore = NULL;
//	HCERTSTORE hCertificateStore = NULL;
//	PCCERT_CONTEXT pCertContext = NULL;
//	PCCERT_CONTEXT pCertContext2 = NULL;
//	LPWSTR wszStoreName = NULL;
//	LPWSTR wszPassword = NULL;
//	CRYPT_DATA_BLOB tCertificateData;
//	OpcUa_ByteString tFileData;
//	std::string privateKeyFile;
//	OpcUa_UInt32 dwFlags = CRYPT_EXPORTABLE;
//
//OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_ImportPrivateKeyToWindowsStore");
//
//	OpcUa_ReturnErrorIfArgumentNull(a_sSourceStorePath);
//
//	memset(&tCertificateData, 0, sizeof(CRYPT_DATA_BLOB));
//	OpcUa_ByteString_Initialize(&tFileData);
//
//	// get the file name for the certificate.
//	privateKeyFile = OpcUa_Certificate_GetFilePathForCertificate(
//		a_sSourceStorePath,
//		a_pCertificate,
//		OpcUa_Crypto_Encoding_PKCS12,
//		OpcUa_False);
//
//	if (privateKeyFile.empty())
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//	}
//
//	// read the certificate from disk.
//	uStatus = OpcUa_ReadFile((OpcUa_StringA)privateKeyFile.c_str(), &tFileData);
//	OpcUa_GotoErrorIfBad(uStatus);
//
//	// import certificate.
//	if (a_bUseMachineStore)
//	{
//		dwFlags |= CRYPT_MACHINE_KEYSET;
//	}
//	else
//	{
//		dwFlags |= CRYPT_USER_KEYSET;
//	}
//
//	uStatus = OpcUa_StringToUnicode(a_sPassword, (OpcUa_Char**)&wszPassword);
//	OpcUa_GotoErrorIfBad(uStatus);
//
//	tCertificateData.pbData = tFileData.Data;
//	tCertificateData.cbData = tFileData.Length;
//
//	hFileStore = PFXImportCertStore(&tCertificateData, wszPassword, dwFlags);
//
//	if (hFileStore == 0)
//	{
//		if (wszPassword == NULL)
//		{
//			hFileStore = PFXImportCertStore(&tCertificateData, L"", dwFlags);
//		}
//		else if (wszPassword[0] == '\0')
//		{
//			hFileStore = PFXImportCertStore(&tCertificateData, NULL, dwFlags);
//		}
//
//		if (hFileStore == 0)
//		{
//			OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
//		}
//	}
//
//	// open the certificate store.
//	dwFlags = 0;
//
//	if (a_bUseMachineStore)
//	{
//		dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
//	}
//	else
//	{
//		dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;
//	}
//
//	uStatus = OpcUa_StringToUnicode(a_sStoreName, (OpcUa_Char**)&wszStoreName);
//	OpcUa_GotoErrorIfBad(uStatus);
//
//	// open the store.
//	hCertificateStore = CertOpenStore(
//		CERT_STORE_PROV_SYSTEM,
//		0,
//		0,
//		dwFlags,
//		wszStoreName);
//
//	if (hCertificateStore == 0)
//	{
//		OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//	}
//
//	// Find the certificates in the system store.
//	while (pCertContext = CertEnumCertificatesInStore(hFileStore, pCertContext))
//	{
//		// add back into store.
//		BOOL bResult = CertAddCertificateContextToStore(
//			hCertificateStore,
//			pCertContext,
//			CERT_STORE_ADD_REPLACE_EXISTING,
//			&pCertContext2);
//
//		if (bResult == 0)
//		{
//			OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
//		}
//
//		CertFreeCertificateContext(pCertContext2);
//		pCertContext2 = NULL;
//	}
//
//	// clean up.
//	CertCloseStore(hFileStore, 0);
//	CertCloseStore(hCertificateStore, 0);
//	OpcUa_Free(tCertificateData.pbData);
//	OpcUa_Free(wszStoreName);
//	OpcUa_Free(wszPassword);
//
//OpcUa_ReturnStatusCode;
//OpcUa_BeginErrorHandling;
//
//	if (pCertContext != NULL)
//	{
//		CertFreeCertificateContext(pCertContext);
//	}
//
//	if (pCertContext2 != NULL)
//	{
//		CertFreeCertificateContext(pCertContext2);
//	}
//
//	if (hFileStore != NULL)
//	{
//		CertCloseStore(hFileStore, 0);
//	}
//
//	if (hCertificateStore != NULL)
//	{
//		CertCloseStore(hCertificateStore, 0);
//	}
//
//	OpcUa_Free(tCertificateData.pbData);
//	OpcUa_Free(wszStoreName);
//	OpcUa_Free(wszPassword);
//
//OpcUa_FinishErrorHandling;
//}

/*============================================================================
 * OpcUa_Certificate_LookupDomainName
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LookupDomainName(
	OpcUa_StringA  a_sAddress,
	OpcUa_StringA* a_pDomainName)
{
	struct sockaddr_in tAddress;
	char sHostname[NI_MAXHOST];
	int iLength = 0;
	int iResult = 0;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_FreeFindContext");

	OpcUa_ReturnErrorIfArgumentNull(a_sAddress);
	OpcUa_ReturnErrorIfArgumentNull(a_pDomainName);

	*a_pDomainName = NULL;

	OpcUa_MemSet(&tAddress, 0, sizeof(tAddress));
	OpcUa_MemSet(sHostname, 0, sizeof(sHostname));

	tAddress.sin_family = AF_INET;
	tAddress.sin_addr.s_addr = inet_addr(a_sAddress);
	tAddress.sin_port = htons(0);

	iResult = getnameinfo(
		(struct sockaddr*)&tAddress,
		sizeof(sockaddr_in),
		sHostname,
		NI_MAXHOST,
		NULL,
		0,
		0);

	if (iResult != 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);
	}

	iLength = strlen(sHostname)+1;
	*a_pDomainName = (OpcUa_StringA)OpcUa_Alloc(iLength);
	OpcUa_GotoErrorIfAllocFailed(*a_pDomainName);
	strcpy(*a_pDomainName, sHostname);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	// nothing to do.

OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_Certificate_LookupLocalhostNames
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LookupLocalhostNames(
	OpcUa_StringA** a_pHostNames,
	OpcUa_UInt32*   a_pNoOfHostNames)
{
	char sBuffer[NI_MAXHOST];
	std::vector<std::string> hostnames;

	struct ifaddrs	*ifaddr, *ifa;
	int iResult;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "sDnsName");

	OpcUa_ReturnErrorIfArgumentNull(a_pHostNames);
	OpcUa_ReturnErrorIfArgumentNull(a_pNoOfHostNames);

	*a_pHostNames = NULL;
	*a_pNoOfHostNames = 0;

	/* get hostname */
	if (gethostname(sBuffer, sizeof(sBuffer)) != 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);
	}
	hostnames.push_back(sBuffer);

	/* get local ip address(es) */
	iResult = getifaddrs( &ifaddr );
	if (iResult == -1)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR,
				"getifaddrs failed iResult = 0x%08X, %s\n",
				iResult, gai_strerror(iResult));
		OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			char str[INET_ADDRSTRLEN];
			// now get it back and print it
			inet_ntop(AF_INET,
					&(((struct sockaddr_in *) ifa->ifa_addr)->sin_addr),
					str, INET_ADDRSTRLEN);

			hostnames.push_back(str);
		}
/*
 * TODO: need to test this with well configured IPV6 host
		if ( ifa->ifa_addr->sa_family == AF_INET6 )
		{
			char str[INET6_ADDRSTRLEN];
			// now get it back and print it
			inet_ntop(AF_INET6,
					&(((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr),
					str, INET6_ADDRSTRLEN);

			hostnames.push_back(str);
		}
*/
	}

	freeifaddrs( ifaddr );

	uStatus = OpcUa_Certificate_CopyStrings(hostnames, a_pHostNames, a_pNoOfHostNames);
	OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (iResult != -1)
	{
		freeifaddrs( ifaddr );
	}

OpcUa_FinishErrorHandling;
}
