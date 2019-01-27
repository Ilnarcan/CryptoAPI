#include "CryptoAPI.h"

PCCERT_CONTEXT GetRecipientCert( 
    HCERTSTORE hCertStore) 
	//------------------------------------------------------------------- 
	// Parameter passed in: 
	// hCertStore, the handle of the store to be searched. 
	{ 
	//------------------------------------------------------------------- 
	// Declare and initialize local variables. 

	PCCERT_CONTEXT pCertContext = NULL; 
	BOOL fMore = TRUE; 
	DWORD dwSize = NULL; 
	CRYPT_KEY_PROV_INFO* pKeyInfo = NULL; 
	DWORD PropId = CERT_KEY_PROV_INFO_PROP_ID; 

	//--------------------------------------------------------------------
	// Find certificates in the store until the end of the store 
	// is reached or a certificate with an AT_KEYEXCHANGE key is found. 

	while(fMore && (pCertContext= CertFindCertificateInStore( 
	   hCertStore, // Handle of the store to be searched. 
	   0,          // Encoding type. Not used for this search. 
	   0,          // dwFindFlags. Special find criteria. 
				   // Not used in this search. 
	   CERT_FIND_PROPERTY, 
				   // Find type. Determines the kind of search 
				   // to be done. In this case, search for 
				   // certificates that have a specific 
				   // extended property. 
	   &PropId,    // pvFindPara. Gives the specific 
				   // value searched for, here the identifier 
				   // of an extended property. 
	   pCertContext))) 
				   // pCertContext is NULL for the  
				   // first call to the function. 
				   // If the function were being called 
				   // in a loop, after the first call 
				   // pCertContext would be the pointer 
				   // returned by the previous call. 
	{ 
	//------------------------------------------------------------------- 
	// For simplicity, this code only searches 
	// for the first occurrence of an AT_KEYEXCHANGE key. 
	// In many situations, a search would also look for a 
	// specific subject name as well as the key type. 

	//-------------------------------------------------------------------
	// Call CertGetCertificateContextProperty once to get the 
	// returned structure size. 

	if(!(CertGetCertificateContextProperty( 
		 pCertContext, 
		 CERT_KEY_PROV_INFO_PROP_ID, 
		 NULL, &dwSize))) 
	{ 
		 MyHandleError("Error getting key property."); 
	} 

	//------------------------------------------------------------------- 
	// Allocate memory for the returned structure. 

	if(pKeyInfo) 
		free(pKeyInfo); 
	if(!(pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwSize))) 
	{ 
		 MyHandleError("Error allocating memory for pKeyInfo."); 
	} 

	//------------------------------------------------------------------- 
	// Get the key information structure. 

	if(!(CertGetCertificateContextProperty( 
	   pCertContext, 
	   CERT_KEY_PROV_INFO_PROP_ID, 
	   pKeyInfo, 
	   &dwSize))) 
	{ 
		MyHandleError("The second call to the function failed."); 
	} 

	//------------------------------------------------------------------- 
	// Check the dwKeySpec member for an exchange key. 

	if(pKeyInfo->dwKeySpec == AT_KEYEXCHANGE) 
	{ 
		fMore = FALSE; } 
	}    // End of while loop 

	if(pKeyInfo) 
		  free(pKeyInfo); 
	return (pCertContext); 
} // End of GetRecipientCert