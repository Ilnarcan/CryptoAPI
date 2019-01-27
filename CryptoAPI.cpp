#include "CryptoAPI.h"

void main( void )
{

	int choice = 0;
	while(choice != 5)
	{
		printf(	"1. Encrypt file\n"
				"2. Decrypt file\n"
				"3. Sign file\n"
				"4. Check signiture\n"
				"5. Exit\n"
				"\nSelect option: ");
		scanf("%i", &choice);
		while(choice < 1 || choice > 5)
		{
			printf("Wrong input data. Try again: ");
			scanf("%i", &choice);
		}

		switch (choice)
		{
		case 1:
			char in[40];
			char out[40];
			printf("\tInput file ");
			scanf("%s", &in);
			printf("\tOutput file ");
			scanf("%s", &out);
			Encrypt(in, out);
			break;
		case 2:
			char in1[40];
			char out1[40];
			printf("\tInput file ");
			scanf("%s", &in1);
			printf("\tOutput file ");
			scanf("%s", &out1);
			
			Decrypt(in1, out1);
			break;
		case 3:
			char in2[40];
			char out2[40];
			printf("\tInput file ");
			scanf("%s", &in2);
			printf("\tOutput file ");
			scanf("%s", &out2);
			SignMessage(in2, out2);
			break;
		case 4:
			char in3[40];
			printf("\tInput file ");
			scanf("%s", &in3);
			VerifySignedMessage(in3);
			break;
		case 5:
			break;
		}
	}
}




void MyHandleError(char *s)
{
    fprintf(stderr,"An error occurred in running the program. \n");
    fprintf(stderr,"%s\n",s);
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of MyHandleError


void ByteToStr(
     DWORD cb, 
     void* pv, 
     LPSTR sz)
//-------------------------------------------------------------------
// Parameters passed are:
//    pv is the array of BYTEs to be converted.
//    cb is the number of BYTEs in the array.
//    sz is a pointer to the string to be returned.

{
//-------------------------------------------------------------------
//  Declare and initialize local variables.

BYTE* pb = (BYTE*) pv; // Local pointer to a BYTE in the BYTE array
DWORD i;               // Local loop counter
int b;                 // Local variable

//-------------------------------------------------------------------
//  Begin processing loop.

for (i = 0; i < cb; i++)
{
   b = (*pb & 0xF0) >> 4;
   *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
   b = *pb & 0x0F;
   *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
   pb++;
}
*sz++ = 0;
} // End of ByteToStr