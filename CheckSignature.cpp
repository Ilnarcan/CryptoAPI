#include "CryptoAPI.h"

#define CERT_STORE_NAME  L"MY"

void VerifySignedMessage( char *srcFilePath )
{
	DWORD cbDecodedMessageBlob = 0;
	BYTE *pbDecodedMessageBlob = NULL;
	CRYPT_VERIFY_MESSAGE_PARA VerifyParams;

	BYTE* pbSignedMessageBlob;					//Message
	DWORD cbSignedMessageBlob = 0;				// Size of message
	
	FILE *src = fopen(srcFilePath, "rb");
	if(src == NULL)
		MyHandleError("File open error");
	int c;
	while((c = fgetc(src)) != EOF)
		cbSignedMessageBlob++;					//Calculating message size
	fclose(src);
	src = fopen(srcFilePath, "rb");
	pbSignedMessageBlob = (BYTE *)malloc(cbSignedMessageBlob * sizeof(BYTE));
	int k = 0;
	while((c = fgetc(src)) != EOF)
		pbSignedMessageBlob[k++] = c;
	fclose(src);

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

	// Initialize the VerifyParams data structure.
	VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
	VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
	VerifyParams.hCryptProv = hCryptProv;
	VerifyParams.pfnGetSignerCertificate = NULL;
	VerifyParams.pvGetArg = NULL;

	// First, call CryptVerifyMessageSignature to get the length 
	// of the buffer needed to hold the decoded message.
	if(CryptVerifyMessageSignature(
		&VerifyParams,
		0,
		pbSignedMessageBlob,
		cbSignedMessageBlob,
		NULL,
		&cbDecodedMessageBlob,
		NULL))
	{
		printf("%d bytes needed for the decoded message.\n",
			cbDecodedMessageBlob);
	}
	else
	{
		printf("Message verification failed. \n");
		free(pbDecodedMessageBlob);
		return;
	}

	//---------------------------------------------------------------
	//   Allocate memory for the decoded message.
	if(!(pbDecodedMessageBlob = 
	   (BYTE*)malloc(cbDecodedMessageBlob)))
	{
		MyHandleError(
			"Memory allocation error allocating decode BLOB.");
	}

	//---------------------------------------------------------------
	// Call CryptVerifyMessageSignature again to verify the signature
	// and, if successful, copy the decoded message into the buffer. 
	// This will validate the signature against the certificate in 
	// the local store.
	if(CryptVerifyMessageSignature(
		&VerifyParams,
		0,
		pbSignedMessageBlob,
		cbSignedMessageBlob,
		pbDecodedMessageBlob,
		&cbDecodedMessageBlob,
		NULL))
	{
		printf("Message verification succeed. \n");
	}
	else
	{
		printf("Message verification failed. \n");
	}

	// If something failed and the decoded message buffer was 
	// allocated, free it.
	if(pbDecodedMessageBlob)
	{
		free(pbDecodedMessageBlob);
		pbDecodedMessageBlob = NULL;
	}


	// If the decoded message buffer is still around, it means the 
	// function was successful. Copy the pointer and size into the 
	// output parameter.
}
