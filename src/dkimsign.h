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

#ifndef DKIMSIGN_H
#define DKIMSIGN_H

#include "dkimbase.h"

class CDKIMSign : public CDKIMBase
{
public:

	CDKIMSign();
	~CDKIMSign();

	int Init( DKIMSignOptions* pOptions );

	int GetSig( char* szPrivKey, char* szSignature, int nSigLength );

	virtual int ProcessHeaders(void);
	virtual int ProcessBody( char* szBuffer, int nBufLength );

	enum CKDKIMConstants { OptimalHeaderLineLength = 65 };

protected:

	void Hash( const char* szBuffer, int nBufLength );

	bool SignThisTag( const string& sTag );
	void GetHeaderParams( const string& sHdr );
	void ProcessHeader( const string& sHdr );
	bool ParseFromAddress( void );

	void InitSig(void);
	void AddTagToSig( char cTag, const string &sValue, char cbrk );
	void AddTagToSig( char cTag, unsigned long nValue );
	void AddInterTagSpace( int nSizeOfNextTag );
	void AddFoldedValueToSig( const string &sValue, char cbrk );

	bool IsRequiredHeader( const string& sTag );

	EVP_MD_CTX m_mdctx;		/* the hash */
	int m_Canon;			// canonization method

	string hParam;
	string sFrom;
	string sSender;
	string sSelector;
	string sDomain;
	string sIdentity;					// for i= tag, if empty tag will not be included in sig
	string sRequiredHeaders;

	bool m_IncludeBodyLengthTag;
	int m_nBodyLength;
	time_t m_ExpireTime;
	int m_nIncludeTimeStamp;					// 0 = don't include t= tag, 1 = include t= tag
	int m_nIncludeQueryMethod;				// 0 = don't include q= tag, 1 = include q= tag


	DKIMHEADERCALLBACK m_pfnHdrCallback;

	string m_sSig;
	int m_nSigPos;

};



#endif // DKIMSIGN_H
