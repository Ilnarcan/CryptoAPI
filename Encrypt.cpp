#include "CryptoAPI.h"


void Encrypt( char *srcFilePath, char *dstFilePath)
{
	//-------------------------------------------------------------------
	// Declare and initialize variables. This includes getting a pointer 
	// to the message to be encrypted. This code creates a message
	// and gets a pointer to it. In reality, the message content 
	// usually exists somewhere and a pointer to the message is 
	// passed to the application.
	#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

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

	HCRYPTPROV hCryptProv;                      // CSP handle
	HCERTSTORE hStoreHandle;
	PCCERT_CONTEXT pRecipientCert;
	PCCERT_CONTEXT RecipientCertArray[1];
	DWORD EncryptAlgSize;
	CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
	CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;
	DWORD EncryptParamsSize;
	BYTE*    pbEncryptedBlob;
	DWORD    cbEncryptedBlob;

	//-------------------------------------------------------------------
	// Get a handle to a cryptographic provider.

	if(CryptAcquireContext(
				&hCryptProv,        // Address for handle to be returned.
				NULL,               // Use the current user's logon name.
				NULL,               // Use the default provider.
				PROV_RSA_FULL,      // Need to both encrypt and sign.
				NULL))              // No flags needed.
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
		MyHandleError( "Error getting store handle.");
	}
	//-------------------------------------------------------------------
	// Get a pointer to the recipient's certificate.
	// by calling GetRecipientCert. 

	if(pRecipientCert = GetRecipientCert(
		 hStoreHandle))
	{
		printf("A recipient's certificate has been acquired. \n");
	}
	else
	{
		printf("No certificate with a CERT_KEY_CONTEXT_PROP_ID \n");
		printf("property and an AT_KEYEXCHANGE private key "
			"available. \n");
		printf("While the message could be encrypted, in this case, \n");
		printf("it could not be decrypted in this program. \n");
		printf("For more information, see the documentation for \n");
		printf("CryptEncryptMessage and CryptDecryptMessage.\n\n");
		MyHandleError( "No Certificate with AT_KEYEXCHANGE "
			"key in store.");
	}
	//-------------------------------------------------------------------
	// Create a RecipientCertArray.

	RecipientCertArray[0] = pRecipientCert;

	//-------------------------------------------------------------------
	// Initialize the algorithm identifier structure.

	EncryptAlgSize = sizeof(EncryptAlgorithm);

	//-------------------------------------------------------------------
	// Initialize the structure to zero.

	memset(&EncryptAlgorithm, 0, EncryptAlgSize);

	//-------------------------------------------------------------------
	// Set the necessary member.

	EncryptAlgorithm.pszObjId = szOID_RSA_RC4;  

	//-------------------------------------------------------------------
	// Initialize the CRYPT_ENCRYPT_MESSAGE_PARA structure. 

	EncryptParamsSize = sizeof(EncryptParams);
	memset(&EncryptParams, 0, EncryptParamsSize);
	EncryptParams.cbSize =  EncryptParamsSize;
	EncryptParams.dwMsgEncodingType = MY_ENCODING_TYPE;
	EncryptParams.hCryptProv = hCryptProv;
	EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm;

	//-------------------------------------------------------------------
	// Call CryptEncryptMessage.

	if(CryptEncryptMessage(
			  &EncryptParams,
			  1,
			  RecipientCertArray,
			  pbContent,
			  cbContent,
			  NULL,
			  &cbEncryptedBlob))
	{
		printf("The encrypted message is %d bytes. \n",cbEncryptedBlob);
	}
	else
	{
		MyHandleError( "Getting EncryptedBlob size failed.");
	}
	//-------------------------------------------------------------------
	// Allocate memory for the returned BLOB.

	if(pbEncryptedBlob = (BYTE*)malloc(cbEncryptedBlob))
	{
		printf("Memory has been allocated for the encrypted BLOB. \n");
	}
	else
	{
		MyHandleError("Memory allocation error while encrypting.");
	}
	//-------------------------------------------------------------------
	// Call CryptEncryptMessage again to encrypt the content.

	if(CryptEncryptMessage(
			  &EncryptParams,
			  1,
			  RecipientCertArray,
			  pbContent,
			  cbContent,
			  pbEncryptedBlob,
			  &cbEncryptedBlob))
	{
		printf( "Encryption succeeded. \n");
	}
	else
	{
		MyHandleError("Encryption failed.");
	}

	FILE *dst = fopen(dstFilePath, "wb");
	for(int i = 0; i < cbEncryptedBlob; i++)
		fputc(pbEncryptedBlob[i], dst);

	fclose(src);
	fclose(dst);

	//-------------------------------------------------------------------
	// Clean up memory.

	CertFreeCertificateContext(pRecipientCert);
	if(CertCloseStore(
			  hStoreHandle, 
			  CERT_CLOSE_STORE_CHECK_FLAG))
	{
		printf("The MY store was closed without incident. \n");
	}
	else
	{
	   printf("Store closed after encryption -- \n"
		  "but not all certificates or CRLs were freed. \n");
	}
	if(hCryptProv)
	{
		CryptReleaseContext(hCryptProv,0);
		printf("The CSP has been released. \n");
	}
	else
	{
		printf("CSP was NULL. \n");
	}
} // End of Encrypt