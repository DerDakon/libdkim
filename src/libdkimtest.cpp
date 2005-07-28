
#ifdef WIN32
#include <windows.h>
#else
#define strnicmp strncasecmp 
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "dkim.h"
#include "dns.h"


int DKIM_CALL SignThisHeader(const char* szHeader)
{
	if( strnicmp( szHeader, "X-", 2 ) == 0 )
	{
		return 0;
	}

	return 1;
}


int DKIM_CALL SelectorCallback(const char* szFQDN, char* szBuffer, int nBufLen )
{
	return 0;
}

int DKIM_CALL PolicyCallback(const char* szFQDN, char* szBuffer, int nBufLen )
{
	return 0;
}



int main(int argc, char* argv[])
{
	int n;
	char* PrivKeyFile = "test.pem";
	char* MsgFile = "test.msg";
	char* OutFile = "signed.msg";
	int nPrivKeyLen;
	char PrivKey[2048];
	char Buffer[1024];
	int BufLen;
	char szSignature[2048];
	time_t t;
	DKIMContext ctxt;
	DKIMSignOptions opts;

	time(&t);

	opts.nCanon = DKIM_CANON_NOWSP;
	opts.nIncludeBodyLengthTag = 0;
	opts.nIncludeQueryMethod = 0;
	opts.nIncludeTimeStamp = 0;
	opts.expireTime = t + 604800;		// expires in 1 week
	strcpy( opts.szSelector, "jon" );
	strcpy( opts.szDomain, "bardenhagen.com" );
	strcpy( opts.szIdentity, "dkimtest@bardenhagen.com" );
	opts.pfnHeaderCallback = SignThisHeader;
	strcpy( opts.szRequiredHeaders, "NonExistant" );

	int nArgParseState = 0;
	bool bSign = true;

	for( n = 1; n < argc; n++ )
	{
		if( argv[n][0] == '-' && strlen(argv[n]) > 1 )
		{
			switch( argv[n][1] )
			{
			case 'v':		// verify
				bSign = false;
				break;

			case 's':		// sign
				bSign = true;
				break;

			case 'c':		// canonicalization
				if( argv[n][2] == 'n' )
				{
					opts.nCanon = DKIM_CANON_NOWSP;
				}
				else
				{
					opts.nCanon = DKIM_CANON_NOWSP;
				}
				break;


			case 'l':		// body length tag
				opts.nIncludeBodyLengthTag = 1;
				break;

			case 'q':		// query method tag
				opts.nIncludeQueryMethod = 1;
				break;

			case 't':		// timestamp tag
				opts.nIncludeTimeStamp = 1;
				break;

			case 'i':		// identity 
				if( argv[n][2] == '-' )
				{
					opts.szIdentity[0] = '\0';
				}
				else
				{
					strcpy( opts.szIdentity, argv[n] + 2 );
				}
				break;

			case 'h':
				printf( "usage: \n" );
				return 0;

			case 'x':		// expire time 
				if( argv[n][2] == '-' )
				{
					opts.expireTime = 0;
				}
				else
				{
					opts.expireTime = t + atoi( argv[n] + 2  );
				}
			}
		}
		else
		{
			switch( nArgParseState )
			{
			case 0:
				MsgFile = argv[n];
				break;
			case 1:
				PrivKeyFile = argv[n];
				break;
			case 2:
				OutFile = argv[n];
				break;
			}
			nArgParseState++;
		}
	}


	if( bSign )
	{
		FILE* PrivKeyFP = fopen( PrivKeyFile, "r" );

		if ( PrivKeyFP == NULL ) 
		{ 
		  printf( "dkimlibtest: can't open private key file %s\n", PrivKeyFile );
		  exit(1);
		}
		nPrivKeyLen = fread( PrivKey, 1, sizeof(PrivKey), PrivKeyFP );
		if (nPrivKeyLen == sizeof(PrivKey)) { /* TC9 */
		  printf( "dkimlibtest: private key buffer isn't big enough, use a smaller private key or recompile.\n");
		  exit(1);
		}
		PrivKey[nPrivKeyLen] = '\0';
		fclose(PrivKeyFP);


		FILE* MsgFP = fopen( MsgFile, "rb" );

		if ( MsgFP == NULL ) 
		{ 
			printf( "dkimlibtest: can't open msg file %s\n", MsgFile );
			exit(1);
		}

		n = DKIMSignInit( &ctxt, &opts );

		while (1) {
			
			BufLen = fread( Buffer, 1, sizeof(Buffer), MsgFP );

			if( BufLen > 0 )
			{
				DKIMSignProcess( &ctxt, Buffer, BufLen );
			}
			else
			{
				break;
			}
		}

		fclose( MsgFP );
		
		n = DKIMSignGetSig( &ctxt, PrivKey, szSignature, sizeof(szSignature) );

		DKIMSignFree( &ctxt );

		FILE* in = fopen( MsgFile, "rb" );
		FILE* out = fopen( OutFile, "wb+" );

		fwrite( szSignature, 1, strlen(szSignature), out );
		fwrite( "\r\n", 1, 2, out );

		while (1) {
			
			BufLen = fread( Buffer, 1, sizeof(Buffer), in );

			if( BufLen > 0 )
			{
				fwrite( Buffer, 1, BufLen, out );
			}
			else
			{
				break;
			}
		}

		fclose( in );
	}
	else
	{
		FILE* in = fopen( MsgFile, "rb" );

		DKIMVerifyOptions vopts;
		vopts.pfnSelectorCallback = NULL; //SelectorCallback;
		vopts.pfnPolicyCallback = NULL; //PolicyCallback;

		n = DKIMVerifyInit( &ctxt, &vopts );

		while (1) {
			
			BufLen = fread( Buffer, 1, sizeof(Buffer), in );

			if( BufLen > 0 )
			{
				DKIMVerifyProcess( &ctxt, Buffer, BufLen );
			}
			else
			{
				break;
			}
		}

		n = DKIMVerifyResults( &ctxt );

		int nSigCount = 0;
		DKIMVerifyDetails* pDetails;
		char szPolicy[512];

		n = DKIMVerifyGetDetails(&ctxt, &nSigCount, &pDetails, szPolicy );

		if( pDetails->nResult >= 0 )
			printf( "Success\n" );
		else
			printf( "Failure\n" );

		DKIMVerifyFree( &ctxt );
	}

	return 0;
}