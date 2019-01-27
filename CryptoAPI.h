#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)



void Encrypt( char *srcFilePath, char *dstFilePath);
void Decrypt( char *srcFilePath, char *dstFilePath);
void SignMessage( char *srcFilePath, char *dstFilePath);
void VerifySignedMessage( char *srcFilePath );
void CSP_List( void );
PCCERT_CONTEXT GetRecipientCert( HCERTSTORE hCertStore );
void MyHandleError(char *s);
void ByteToStr( DWORD cb, void* pv, LPSTR sz );