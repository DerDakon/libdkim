/*****************************************************************************
*  Copyright 2005 Alt-N Technologies, Ltd. 
*
*  Licensed under the Apache License, Version 2.0 (the "License"); 
*  you may not use this file except in compliance with the License. 
*  You may obtain a copy of the License at 
*
*      http://www.apache.org/licenses/LICENSE-2.0 
*
*  Unless required by applicable law or agreed to in writing, software 
*  distributed under the License is distributed on an "AS IS" BASIS, 
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
*  See the License for the specific language governing permissions and 
*  limitations under the License.
*****************************************************************************/

#ifdef WIN32
#include <windows.h>
#pragma warning( disable: 4786 )
#pragma warning( disable: 4503 )
#else
#define strnicmp strncasecmp 
#define stricmp strcasecmp 
#endif

#include <string.h>
#include <map>

#include "dkim.h"
#include "dkimsign.h"


CDKIMSign::CDKIMSign()
{
	EVP_SignInit( &m_mdctx, EVP_sha1() );
	m_pfnHdrCallback = NULL;
}

CDKIMSign::~CDKIMSign()
{
	EVP_MD_CTX_cleanup( &m_mdctx );
}

////////////////////////////////////////////////////////////////////////////////
// 
// Init - save the options
//
////////////////////////////////////////////////////////////////////////////////
int CDKIMSign::Init( DKIMSignOptions* pOptions )
{
	int nRet = CDKIMBase::Init();

	m_Canon = pOptions->nCanon;

	// as of draft 01, these are the only allowed signing types:
	if(     (m_Canon != DKIM_SIGN_SIMPLE_RELAXED) 
		 && (m_Canon != DKIM_SIGN_RELAXED)
		 && (m_Canon != DKIM_SIGN_RELAXED_SIMPLE) )
	{
		m_Canon = DKIM_SIGN_SIMPLE;
	}

	sSelector.assign( pOptions->szSelector );

	m_pfnHdrCallback = pOptions->pfnHeaderCallback;

	sDomain.assign( pOptions->szDomain );

	m_IncludeBodyLengthTag = ( pOptions->nIncludeBodyLengthTag != 0 );

	m_nBodyLength = 0;

	m_ExpireTime = pOptions->expireTime;

	sIdentity.assign( pOptions->szIdentity );

	m_nIncludeTimeStamp = pOptions->nIncludeTimeStamp;
	
	m_nIncludeQueryMethod = pOptions->nIncludeQueryMethod;

	// NOTE: the following line is not backwards compatible with MD 8.0.3
	// because the szRequiredHeaders member was added after the release
//	sRequiredHeaders.assign( pOptions->szRequiredHeaders );

	//make sure there is a colon after the last header in the list
	if( (sRequiredHeaders.size() > 0) && sRequiredHeaders.at(sRequiredHeaders.size()-1) != ':' )
	{
		sRequiredHeaders.append( ":" );
	}

	return nRet;
}

//FILE* fpdebug = NULL;


////////////////////////////////////////////////////////////////////////////////
// 
// Hash - update the hash
//
////////////////////////////////////////////////////////////////////////////////
void CDKIMSign::Hash( const char* szBuffer, int nBufLength )
{
	/** START DEBUG CODE **
	if( nBufLength == 2 && szBuffer[0] == '\r' && szBuffer[1] == '\n' )
	{
		printf( "[CRLF]\n" );
	}
	else
	{
		char* szDbg = new char[nBufLength+1];
		strncpy( szDbg, szBuffer, nBufLength );
		szDbg[nBufLength] = '\0';
		printf( "[%s]\n", szDbg );
	} ***

	if( fpdebug == NULL )
	{
		fpdebug = fopen( "canon.msg", "wb" );
	}

	fwrite( szBuffer, 1, nBufLength, fpdebug );

	/** END DEBUG CODE **/

	EVP_SignUpdate( &m_mdctx, szBuffer, nBufLength );
}


////////////////////////////////////////////////////////////////////////////////
// 
// SignThisTag - return boolean whether or not to sign this tag
//
////////////////////////////////////////////////////////////////////////////////
bool CDKIMSign::SignThisTag( const string& sTag )
{
	bool bRet = true;

	if( strnicmp( sTag.c_str(), "X-", 2 ) == 0 || 
		stricmp( sTag.c_str(), "Authentication-Results:" ) == 0 ||
		stricmp( sTag.c_str(), "Return-Path:" ) == 0 )
	{
		bRet = false;
	}

	return bRet;
}

////////////////////////////////////////////////////////////////////////////////
// 
// GetHeaderParams - Extract any needed header parameters
//
////////////////////////////////////////////////////////////////////////////////
void CDKIMSign::GetHeaderParams( const string& sHdr )
{
	if( strnicmp( sHdr.c_str(), "From:", 5 ) == 0 )
	{
		sFrom.assign( sHdr.c_str() + 5 );
	}
	if( strnicmp( sHdr.c_str(), "Sender:", 7 ) == 0 )
	{
		sSender.assign( sHdr.c_str() + 7 );
	}
}


////////////////////////////////////////////////////////////////////////////////
// 
// ProcessHeaders - sign headers and save needed parameters
//
////////////////////////////////////////////////////////////////////////////////
int CDKIMSign::ProcessHeaders(void)
{
	map<string,list<string>::reverse_iterator> IterMap;
	map<string,list<string>::reverse_iterator>::iterator IterMapIter;
	list<string>::reverse_iterator riter;
	list<string>::iterator iter;
	string sTag;
	bool bFromHeaderFound = false;

	// walk the header list
	for( iter = HeaderList.begin(); iter != HeaderList.end(); iter++ )
	{
		sTag.assign( *iter );

		// look for a colon
		string::size_type pos = sTag.find( ':' );

		if (pos != string::npos)
		{
			int nSignThisTag = 1;

			// hack off anything past the colon
			sTag.erase( pos + 1, string::npos );

			// is this the From: header?
			if( stricmp( sTag.c_str(), "From:" ) == 0 )
			{
				bFromHeaderFound = true;
				nSignThisTag = 1;
				IsRequiredHeader( sTag );  // remove from required header list
			}
			// is this in the list of headers that must be signed?
			else if( IsRequiredHeader( sTag ) )
			{
				nSignThisTag = 1;
			}
			else
			{
				if( m_pfnHdrCallback )
				{
					nSignThisTag = m_pfnHdrCallback( iter->c_str() );
				}
				else
				{
					nSignThisTag = SignThisTag( sTag ) ? 1 : 0;
				}
			}

			// save header parameters
			GetHeaderParams( *iter );

			if( nSignThisTag > 0 )
			{
				// add this tag to h=
				hParam.append( sTag );

				IterMapIter = IterMap.find( sTag );

				riter = ( IterMapIter == IterMap.end() ) ? HeaderList.rbegin() : IterMapIter->second;
			
				// walk the list in reverse looking for the last instance of this header
				while ( riter != HeaderList.rend() )
				{
					if( strnicmp( riter->c_str(), sTag.c_str(), sTag.size() ) == 0 )
					{
						ProcessHeader( *riter );

						// save the reverse iterator position for this tag
						riter++;
						IterMap[sTag] = riter;
						break;
					}
					riter++;
				} 
			}
		}
	}

	Hash( "\r\n", 2 );

	if( !bFromHeaderFound )
	{
		string sFrom( "From:" );
		hParam.append( sFrom );
		IsRequiredHeader( sFrom ); // remove from required header list
//		Hash( "\r\n", 2 );
	}

	hParam.append( sRequiredHeaders );

//	string::size_type end = sRequiredHeaders.find( ':' );
//	while (end != string::npos)
//	{
//		Hash( "\r\n", 2 );
//		end = sRequiredHeaders.find( ':', end+1 );
//	}

	// remove the last colon from h=
	if( hParam.at( hParam.size() - 1 ) == ':' )
		hParam.erase( hParam.size() - 1, string::npos );

	return DKIM_SUCCESS;
}



void CDKIMSign::ProcessHeader( const string& sHdr )
{
	switch( HIWORD( m_Canon ) )
	{
	case DKIM_CANON_SIMPLE:
		Hash( sHdr.c_str(), sHdr.size() );
		Hash( "\r\n", 2 );
		break;

	case DKIM_CANON_NOWSP:
		{
			string sTemp = sHdr;
			RemoveSWSP( sTemp );

			// convert characters before ':' to lower case
			for( char* s = (char*)sTemp.c_str(); *s != '\0' && *s != ':'; s++ )
			{
				if( *s >= 'A' && *s <= 'Z' )
					*s += 'a'-'A';
			}

			Hash( sTemp.c_str(), sTemp.size() );
			Hash( "\r\n", 2 );
		}
		break;

	case DKIM_CANON_RELAXED:
		{
			string sTemp = RelaxHeader( sHdr );
			Hash( sTemp.c_str(), sTemp.length() );
			Hash( "\r\n", 2 );
		}
		break;	
	}
}


int CDKIMSign::ProcessBody( char* szBuffer, int nBufLength )
{
	switch( LOWORD( m_Canon ) )
	{
	case DKIM_CANON_SIMPLE:
		if( nBufLength > 0 )
			Hash( szBuffer, nBufLength );
		Hash( "\r\n", 2 );
		m_nBodyLength += nBufLength + 2;
		break;

	case DKIM_CANON_NOWSP:
		RemoveSWSP( szBuffer, nBufLength );
		if( nBufLength > 0 )
			Hash( szBuffer, nBufLength );
		m_nBodyLength += nBufLength;
		break;

	case DKIM_CANON_RELAXED:
		CompressSWSP( szBuffer, nBufLength );
		if( nBufLength > 0 )
			Hash( szBuffer, nBufLength );
		Hash( "\r\n", 2 );
		m_nBodyLength += nBufLength + 2;
		break;
	}

	return DKIM_SUCCESS;
}

bool CDKIMSign::ParseFromAddress( void )
{
	string::size_type pos;
	string sAddress;

	if( !sFrom.empty() )
	{
		sAddress.assign( sFrom );
	}
	else if( !sSender.empty() )
	{
		sAddress.assign( sSender );
	}
	else
	{
		return false;
	}

	// simple for now, beef it up later

	// remove '<' and anything before it
	pos = sAddress.find( '<' );
	if( pos != string::npos )
		sAddress.erase( 0, pos );

	// remove '>' and anything after it
	pos = sAddress.find( '>' );
	if( pos != string::npos )
		sAddress.erase( pos, string::npos );

	// look for '@' symbol
	pos = sAddress.find( '@' );
	if( pos == string::npos )
		return false;

	if( sDomain.empty() )
	{
		sDomain.assign( sAddress.c_str() + pos + 1 );
		RemoveSWSP( sDomain );
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////
// 
// InitSig - initialize signature folding algorithm
//
////////////////////////////////////////////////////////////////////////////////
void CDKIMSign::InitSig(void)
{
	m_sSig.reserve( 1024 );
	m_sSig.assign( "DKIM-Signature:" );
	m_nSigPos = m_sSig.size();
}

////////////////////////////////////////////////////////////////////////////////
// 
// AddTagToSig - add tag and value to signature folding if necessary
//               if cbrk == 0, don't fold value, otherwise fold at cbrk char
//
////////////////////////////////////////////////////////////////////////////////
void CDKIMSign::AddTagToSig( char cTag, const string &sValue, char cbrk )
{
	AddInterTagSpace( (cbrk == 0) ? sValue.size() + 3 : 3 );

	m_sSig.append( 1, cTag );
	m_sSig.append( "=" );
	m_nSigPos += 2;

	if( cbrk == 0 )
	{
		m_sSig.append( sValue );
		m_nSigPos += sValue.size();
	}
	else
	{
		AddFoldedValueToSig( sValue, cbrk );
	}
	m_sSig.append( ";" );
	m_nSigPos++;
}

////////////////////////////////////////////////////////////////////////////////
// 
// AddTagToSig - add tag and numeric value to signature folding if necessary
//
////////////////////////////////////////////////////////////////////////////////
void CDKIMSign::AddTagToSig( char cTag, unsigned long nValue )
{
	char szValue[64];
	sprintf( szValue, "%u", nValue );
	AddTagToSig( cTag, szValue, 0 );
}

////////////////////////////////////////////////////////////////////////////////
// 
// AddInterTagSpace - add space or fold here
//
////////////////////////////////////////////////////////////////////////////////
void CDKIMSign::AddInterTagSpace( int nSizeOfNextTag )
{
	if( m_nSigPos + nSizeOfNextTag + 1 > OptimalHeaderLineLength )
	{
		m_sSig.append( "\r\n\t" );
		m_nSigPos = 1;
	}
	else
	{
		m_sSig.append( " " );
		m_nSigPos++;
	}
}

////////////////////////////////////////////////////////////////////////////////
// 
// AddTagToSig - add value to signature folding if necessary
//               if cbrk == 0 fold anywhere, otherwise fold only at cbrk
//
////////////////////////////////////////////////////////////////////////////////
void CDKIMSign::AddFoldedValueToSig( const string &sValue, char cbrk )
{
	string::size_type pos = 0;

	if( cbrk == 0 )
	{
		// fold anywhere
		while( pos < sValue.size() )
		{
			string::size_type len = OptimalHeaderLineLength - m_nSigPos;
			m_sSig.append( sValue.substr( pos, len ) );
			m_nSigPos += len;
			pos += len;

			if( pos < sValue.size() )
			{
				m_sSig.append( "\r\n\t" );
				m_nSigPos = 1;
			}
		}
	}
	else
	{
		// fold only at cbrk
		while( pos < sValue.size() )
		{
			string::size_type len = OptimalHeaderLineLength - m_nSigPos;
			string::size_type brkpos;
			
			if( sValue.size() - pos < len )
			{
				brkpos = sValue.size();
			}
			else
			{
				brkpos = sValue.rfind( cbrk, pos + len );
			}

			if( brkpos == string::npos || brkpos < pos )
			{
				brkpos = sValue.find( cbrk, pos );
				if( brkpos == string::npos )
				{
					brkpos = sValue.size();
				}
			}

			len = brkpos - pos + 1;

			m_sSig.append( sValue.substr( pos, len ) );

			m_nSigPos += len;
			pos += len;

			if( pos < sValue.size() )
			{
				m_sSig.append( "\r\n\t" );
				m_nSigPos = 1;
			}
		}
	}
}


////////////////////////////////////////////////////////////////////////////////
// 
// GetSig - compute hash and return signature header in szSignature
//
////////////////////////////////////////////////////////////////////////////////
int CDKIMSign::GetSig( char* szPrivKey, char* szSignature, int nSigLength )
{
//	char WorkBuffer[512];
	string sSignedSig;
    EVP_PKEY *pkey;
    BIO *bio, *b64;
	unsigned int siglen;
	unsigned char* sig;
	int size;
	int len;
	char* buf;
	int pos = 0;

	if( szPrivKey == NULL )
	{
		return DKIM_BAD_PRIVATE_KEY;
	}

	if( szSignature == NULL )
	{
		return DKIM_BUFFER_TOO_SMALL;
	}

	ProcessFinal();

	if( ParseFromAddress() == false )
	{
		//return DKIM_NO_SENDER;
	}

	Hash( "\r\n", 2 );

	// construct the DKIM-Signature: header and add to hash
	InitSig();

	AddTagToSig( 'a', "rsa-sha1", 0 );

	switch( m_Canon )
	{
	case DKIM_SIGN_SIMPLE:
		AddTagToSig( 'c', "simple", 0 );
		break;
	case DKIM_SIGN_SIMPLE_RELAXED:
		AddTagToSig( 'c', "simple/relaxed", 0 );
		break;
	case DKIM_SIGN_RELAXED:
		AddTagToSig( 'c', "relaxed/relaxed", 0 );
		break;
	case DKIM_SIGN_RELAXED_SIMPLE:
		AddTagToSig( 'c', "relaxed", 0 );
		break;
	}

	AddTagToSig( 'd', sDomain, 0 );

	AddTagToSig( 's', sSelector, 0 );

	if( m_IncludeBodyLengthTag )
	{
		AddTagToSig( 'l', m_nBodyLength );
	}

	if( m_nIncludeTimeStamp != 0 )
	{
		time_t t;
		time( &t );
		AddTagToSig( 't', t );
	}

	if( m_ExpireTime != 0 )
	{
		AddTagToSig( 'x', m_ExpireTime );
	}

	if( !sIdentity.empty() )
	{
		AddTagToSig( 'i', sIdentity, 0 );
	}
	
	if( m_nIncludeQueryMethod )
	{
		AddTagToSig( 'q', "dns", 0 );
	}

	AddTagToSig( 'h', hParam, ':' );

	AddInterTagSpace( 3 );

	m_sSig.append( "b=" );

	// Force a full copy - no reference copies please
	sSignedSig.assign( m_sSig.c_str() );

	if( HIWORD(m_Canon) == DKIM_CANON_RELAXED )
	{
		string sTemp = RelaxHeader( sSignedSig );
		Hash( sTemp.c_str(), sTemp.size() );
	}
	else
	{
		Hash( sSignedSig.c_str(), sSignedSig.size() );
	}

//	fclose( fpdebug );
//	fpdebug = NULL;

    bio = BIO_new_mem_buf(szPrivKey, -1);
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) 
	{
		return DKIM_BAD_PRIVATE_KEY;
	}

    siglen = EVP_PKEY_size(pkey);
    sig = (unsigned char*) OPENSSL_malloc(siglen);
    EVP_SignFinal(&m_mdctx, sig, &siglen, pkey);
    EVP_PKEY_free(pkey);

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
      return DKIM_OUT_OF_MEMORY; 
    }
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
      BIO_free(bio);
      return DKIM_OUT_OF_MEMORY;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    if (BIO_write(b64, sig, siglen) < siglen) {
      OPENSSL_free(sig);
      BIO_free_all(b64);
      return DKIM_OUT_OF_MEMORY;
    }
    BIO_flush(b64);
    OPENSSL_free(sig);

	len = siglen * 2;
	buf = new char[len];

	if( buf == NULL )
		return DKIM_OUT_OF_MEMORY;

    size = BIO_read(bio, buf, len);
    BIO_free_all(b64);

	// this should never happen
    if (size >= len) 
		return DKIM_OUT_OF_MEMORY;  

    buf[size] = '\0';

	AddFoldedValueToSig( buf, 0 );

	if( m_sSig.size() + 1 < nSigLength )
	{
		strcpy( szSignature, m_sSig.c_str() );
	}
	else
	{
		return DKIM_BUFFER_TOO_SMALL; 
	}

	return DKIM_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////
// 
// IsRequiredHeader - Check if header in required list. If so, delete
//                    header from list.
//
////////////////////////////////////////////////////////////////////////////////
bool CDKIMSign::IsRequiredHeader( const string& sTag )
{
	string::size_type start = 0;
	string::size_type end = sRequiredHeaders.find( ':' );

	while (end != string::npos)
	{
		// check for a zero-length header
		if( start == end )
		{
			sRequiredHeaders.erase( start, 1 );
		}
		else
		{
			if( stricmp( sTag.c_str(), sRequiredHeaders.substr( start, end - start + 1 ).c_str() ) == 0 )
			{
				sRequiredHeaders.erase( start, end - start + 1 );
				return true;
			}
			else
			{
				start = end + 1;
			}
		}

		end = sRequiredHeaders.find( ':', start );
	}

	return false;
}
