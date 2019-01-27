#include "CryptoAPI.h"

#define CERT_STORE_NAME  L"MY"

void SignMessage( char *srcFilePath, char *dstFilePath)
{
	BYTE* pbContent;					//Message
	DWORD cbContent = 0;				// Size of message
	
	FILE *src = fopen(srcFilePath, "rb");
	if(src == NULL)
		MyHandleError("File open error");
	int c;
	while((c = fgetc(src)) != EOF)
		cbContent++;					//Calculating message size
	fclose(src);
	src = fopen(srcFilePath, "rb");
	pbContent = (BYTE *)malloc(cbContent * sizeof(BYTE));
	int k = 0;
	while((c = fgetc(src)) != EOF)
		pbContent[k++] = c;

	HCERTSTORE hCertStore = NULL;   
	PCCERT_CONTEXT pSignerCert; 
	CRYPT_SIGN_MESSAGE_PARA  SigParams;
	DWORD cbSignedMessageBlob;
	BYTE  *pbSignedMessageBlob = NULL;

	//// The message to be signed.
	//// Usually, the message exists somewhere and a pointer is
	//// passed to the application.
	//pbMessage = 
	//	(BYTE*)TEXT("CryptoAPI is a good way to handle security");

	//// Calculate the size of message. To include the 
	//// terminating null character, the length is one more byte 
	//// than the length returned by the strlen function.
	//cbMessage = (lstrlen((TCHAR*) pbMessage) + 1) * sizeof(TCHAR);

	// Create the MessageArray and the MessageSizeArray.
	const BYTE* MessageArray[] = {pbContent};
	DWORD_PTR MessageSizeArray[1];
	MessageSizeArray[0] = cbContent;
	
	HCRYPTPROV hCryptProv;                      // CSP handle
	HCERTSTORE hStoreHandle;
   
	//-------------------------------------------------------------------
	// Get a handle to a cryptographic provider.

	if(CryptAcquireContext(
				&hCryptProv,	// Address for handle to be returned.
				NULL,			// Use the current user's logon name.
				NULL,			// Use the default provider.
				PROV_RSA_FULL,	  // Need to both encrypt and sign.
				NULL))			// No flags needed.
	{
		printf("A CSP has been acquired. \n");
	}
	else
	{
		MyHandleError("Cryptographic context could not be acquired.");
	}
	//-------------------------------------------------------------------
	// Open a system certificate store.

	if(hStoreHandle = CertOpenSystemStore(
		 hCryptProv, 
		 "MY"))
	{
		printf("The MY store is open. \n");
	}
	else
	{
		MyHandleError("Error getting store handle.");
	}

	// Get a pointer to the signer's certificate.
	// This certificate must have access to the signer's private key.
	if(pSignerCert = CertFindCertificateInStore(
	   hStoreHandle,
	   MY_ENCODING_TYPE,
	   0,
	   CERT_FIND_ANY,
	   NULL,
	   NULL))
   {
		printf("A certificate has been acquired. \n");
	}
	else
	{
		printf("No certificate with a CERT_KEY_CONTEXT_PROP_ID \n");
		printf("property and an AT_KEYEXCHANGE private key "
			"available. \n");
		MyHandleError( "No Certificate with AT_KEYEXCHANGE "
			"key in store.");
	}

	// Initialize the signature structure.
	SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
	SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
	SigParams.pSigningCert = pSignerCert;
	SigParams.HashAlgorithm.pszObjId = szOID_RSA_MD5;
	SigParams.HashAlgorithm.Parameters.cbData = NULL;
	SigParams.cMsgCert = 1;
	SigParams.rgpMsgCert = &pSignerCert;
	SigParams.cAuthAttr = 0;
	SigParams.dwInnerContentType = 0;
	SigParams.cMsgCrl = 0;
	SigParams.cUnauthAttr = 0;
	SigParams.dwFlags = 0;
	SigParams.pvHashAuxInfo = NULL;
	SigParams.rgAuthAttr = NULL;

	// First, get the size of the signed BLOB.
	if(CryptSignMessage(
		&SigParams,					// Signature parameters
		FALSE,						// Not detached
		1,							// Number of messages
		MessageArray,				// Messages to be signed
		MessageSizeArray,			// Size of messages
		NULL,						// Buffer for signed message
		&cbSignedMessageBlob))		// Size of buffer
	{
		printf("%d bytes needed for the encoded BLOB.\n",
			cbSignedMessageBlob);
	}
	else
	{
		MyHandleError("Getting signed BLOB size failed");
   }

	// Allocate memory for the signed BLOB.
	if(!(pbSignedMessageBlob = 
	   (BYTE*)malloc(cbSignedMessageBlob)))
	{
		MyHandleError("Memory allocation error while signing.");
	}

	// Get the signed message BLOB.
	if(CryptSignMessage(
		  &SigParams,
		  FALSE,
		  1,
		  MessageArray,
		  MessageSizeArray,
		  pbSignedMessageBlob,
		  &cbSignedMessageBlob))
	{
		printf("The message was signed successfully. \n");

		// pbSignedMessageBlob now contains the signed BLOB.
	}
	else
	{
		MyHandleError("Error getting signed BLOB");
	}

	// Clean up and free memory as needed.
	if(pSignerCert)
	{
		CertFreeCertificateContext(pSignerCert);
	}
	
	if(hCertStore)
	{
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
		hCertStore = NULL;
	}

	FILE *dst = fopen(dstFilePath, "wb");
	for(int i = 0; i < cbSignedMessageBlob; i++)
		fputc(pbSignedMessageBlob[i], dst);

	fclose(src);
	fclose(dst);

	free(pbSignedMessageBlob);
}