#include "CryptoAPI.h"

//-------------------------------------------------------------------
	//  Define the function DecryptMessage.

void Decrypt( char *srcFilePath, char *dstFilePath)
{

	//BOOL DecryptMessage( 
	//BYTE *pbEncryptedBlob, 
	//DWORD cbEncryptedBlob,
	//HCRYPTPROV hCryptProv,
	//HCERTSTORE hStoreHandle)
	//-------------------------------------------------------------------
	// Example function for decrypting an encrypted message using
	// CryptDecryptMessage. Its parameters are pbEncryptedBlob,
	// an encrypted message; cbEncryptedBlob, the length of that
	// message; hCryptProv, a CSP; and hStoreHandle, the handle
	// of an open certificate store.

	//-------------------------------------------------------------------
	// Declare and initialize local variables.


	
	DWORD cbDecryptedMessage;
	CRYPT_DECRYPT_MESSAGE_PARA  DecryptParams;
	DWORD  DecryptParamsSize = sizeof(DecryptParams);
	BYTE*  pbDecryptedMessage;
	LPSTR  DecryptedString;
	
	HCRYPTPROV hCryptProv;
	HCERTSTORE hStoreHandle;

	//!!!!!!!!!!!!!!!!!!!!!!!!!!
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

	//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	HCERTSTORE CertStoreArray[] = {hStoreHandle};

	//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


	BYTE* pbEncryptedBlob;					//Message
	DWORD cbEncryptedBlob = 0;				// Size of message
	
	FILE *src = fopen(srcFilePath, "rb");
	if(src == NULL)
		MyHandleError("File open error");
	int c;
	while((c = fgetc(src)) != EOF)
		cbEncryptedBlob++;					//Calculating message size
	fclose(src);
	src = fopen(srcFilePath, "rb");
	pbEncryptedBlob = (BYTE *)malloc(cbEncryptedBlob * sizeof(BYTE));
	int k = 0;
	while((c = fgetc(src)) != EOF)
		pbEncryptedBlob[k++] = c;

	//char *str;
	//ByteToStr(cbEncryptedBlob, pbEncryptedBlob, str);
	//printf("\n! Encrypted data: %s \n", str);

	//-------------------------------------------------------------------
	// Get a pointer to the encrypted message, pbEncryptedBlob,
	// and its length, cbEncryptedBlob. In this example, these are
	// passed as parameters along with a CSP and an open store handle.

	//-------------------------------------------------------------------
	// View the encrypted BLOB.
	// Call a function, ByteToStr, to convert the byte BLOB to ASCII
	// hexadecimal format. 

	//!ByteToStr(
	//!	cbEncryptedBlob, 
	//!	pbEncryptedBlob, 
	//!	EncryptedString);

	//-------------------------------------------------------------------
	// Print the converted string.

	//!printf("The encrypted string is: \n%s\n",EncryptedString);

	//-------------------------------------------------------------------
	//   In this example, the handle to the MY store was passed in as a 
	//   parameter. 

	//-------------------------------------------------------------------
	//   Create a "CertStoreArray."
	//   In this example, this step was done in the declaration
	//   and initialization of local variables because the store handle 
	//   was passed into the function as a parameter.

	//-------------------------------------------------------------------
	//   Initialize the CRYPT_DECRYPT_MESSAGE_PARA structure.

	memset(&DecryptParams, 0, DecryptParamsSize);
	DecryptParams.cbSize = DecryptParamsSize;
	DecryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
	DecryptParams.cCertStore = 1;
	DecryptParams.rghCertStore = CertStoreArray;

	//-------------------------------------------------------------------
	//  Decrypt the message data.
	//  Call CryptDecryptMessage to get the returned data size.

	if(CryptDecryptMessage(
			  &DecryptParams,
			  pbEncryptedBlob,
			  cbEncryptedBlob,
			  NULL,
			  &cbDecryptedMessage,
			  NULL))
	{
		printf("The size for the decrypted message is: %d.\n",
			cbDecryptedMessage);
	}
	else
	{
		MyHandleError( "Error getting decrypted message size");
	}
	//-------------------------------------------------------------------
	// Allocate memory for the returned decrypted data.

	if(pbDecryptedMessage = (BYTE*)malloc(
		   cbDecryptedMessage))
	{
		printf("Memory has been allocated for the decrypted message. "
			"\n");
	}
	else
	{
		MyHandleError("Memory allocation error while decrypting");
	}
	//-------------------------------------------------------------------
	// Call CryptDecryptMessage to decrypt the data.

	if(CryptDecryptMessage(
			  &DecryptParams,
			  pbEncryptedBlob,
			  cbEncryptedBlob,
			  pbDecryptedMessage,
			  &cbDecryptedMessage,
			  NULL))
	{
		//!DecryptedString = (LPSTR) pbDecryptedMessage;
		printf("Message Decrypted Successfully. \n");
		//!printf("The decrypted string is: %s\n",DecryptedString);
		FILE *dst = fopen(dstFilePath, "wb");
		for(int i = 0; i < cbDecryptedMessage; i++)
			fputc(pbDecryptedMessage[i], dst);
		fclose(dst);
	}
	else
	{
		printf("Error decrypting the message \n");
		printf("Error code %x \n", GetLastError());
	}

	//-------------------------------------------------------------------
	// Clean up memory.

	free(pbEncryptedBlob);
	free(pbDecryptedMessage);

	fclose(src);
}  // End of DecryptMessage

//-------------------------------------------------------------------
// Define the function ByteToStr.

//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.


//-------------------------------------------------------------------
// GetRecipientCert enumerates the certificates in a store and finds
// the first certificate that has an AT_EXCHANGE key. If a  
// certificate is found, a pointer to that certificate is returned.  

