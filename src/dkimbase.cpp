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
#else
#endif

#include <string.h>

#include "dkim.h"
#include "dkimbase.h"

#include <algorithm>


CDKIMBase::CDKIMBase()
{
	m_From = NULL;
	m_Sender = NULL;
	m_hTag = NULL;
	m_hTagSize = 0;
	m_hTagPos = 0;
	m_Line = NULL;
	m_LineSize = 0;
	m_LinePos = 0;
	m_InHeaders = true;
	m_EmptyLineCount = 0;
}

CDKIMBase::~CDKIMBase()
{
	Free( m_Line );
	Free( m_From );
	Free( m_Sender );
	Free( m_hTag );
}

int CDKIMBase::Init(void)
{
	return DKIM_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// 
// Alloc - allocate buffer
//
////////////////////////////////////////////////////////////////////////////////
int CDKIMBase::Alloc( char*& szBuffer, int nRequiredSize )
{
	szBuffer = new char[nRequiredSize];

	return (szBuffer == NULL) ? DKIM_OUT_OF_MEMORY : DKIM_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////
// 
// ReAlloc - extend buffer if necessary, leaving room for future expansion
//
////////////////////////////////////////////////////////////////////////////////
int CDKIMBase::ReAlloc( char*& szBuffer, int& nBufferSize, int nRequiredSize )
{
	if( nRequiredSize > nBufferSize )
	{
		char* newp;
		int nNewSize = nRequiredSize + BUFFER_ALLOC_INCREMENT; 

		if( Alloc( newp, nNewSize ) == DKIM_SUCCESS )
		{
			if( szBuffer != NULL && nBufferSize > 0 )
			{
				memcpy( newp, szBuffer, nBufferSize );
				delete[] szBuffer;
			}
			szBuffer = newp;
			nBufferSize  = nNewSize;
		}
		else
		{
			return DKIM_OUT_OF_MEMORY; // memory alloc error!
		}
	}

	return DKIM_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// 
// Process - split buffers into lines without any CRs or LFs at the end.
//
////////////////////////////////////////////////////////////////////////////////
void CDKIMBase::Free( char* szBuffer )
{
	if( szBuffer )
		delete[] szBuffer;
}

////////////////////////////////////////////////////////////////////////////////
// 
// Process - split buffers into lines without any CRs or LFs at the end.
//
////////////////////////////////////////////////////////////////////////////////
int CDKIMBase::Process( char* szBuffer, int nBufLength )
{
	char* p = szBuffer;
	char* e = szBuffer + nBufLength;

	while( p < e )
	{
		if( *p != '\n' || m_LinePos == 0 || m_Line[m_LinePos-1] != '\r' )
		{
			// add char to line
			if (m_LinePos >= m_LineSize)
			{
				int nRet = ReAlloc( m_Line, m_LineSize, m_LinePos+1 );
				if (nRet != DKIM_SUCCESS)
					return nRet;
			}
			m_Line[m_LinePos++] = *p;
		}
		else
		{
			// back up past the CR
			m_LinePos--;

			if( m_LinePos == 0 )
			{
				// empty line found.  count it but do not process it
				m_EmptyLineCount++;
			}
			else
			{
				// non-empty line found.  process any pending empty lines
				while( m_EmptyLineCount > 0 )
				{
					if( m_InHeaders )
					{
						m_InHeaders = false;
						int Result = ProcessHeaders();
						if (Result != DKIM_SUCCESS)
							return Result;
					}
					else
					{
						int Result = ProcessBody("", 0);
						if (Result != DKIM_SUCCESS)
							return Result;
					}
					m_EmptyLineCount--;
				}

				// process the current line
				if( m_InHeaders )
				{
					// append the header to the headers list
					if ( m_Line[0] != ' ' && m_Line[0] != '\t' )
					{
						HeaderList.push_back( string( m_Line, m_LinePos ) );
					}
					else
					{
						if ( !HeaderList.empty() )
						{
							HeaderList.back().append( "\r\n", 2 ).append( m_Line, m_LinePos );
						}
						else
						{
							// no header to append to...
						}
					}
				}
				else
				{
					int Result = ProcessBody(m_Line, m_LinePos);
					if (Result != DKIM_SUCCESS)
						return Result;
				}

				m_LinePos = 0;
			}
		}

		p++;
	}

	return DKIM_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////
// 
// ProcessFinal - process leftovers if stopping before the body or mid-line
//
////////////////////////////////////////////////////////////////////////////////
int CDKIMBase::ProcessFinal(void)
{
	if ( m_LinePos > 0 )
	{
		Process( "\r\n", 2 );
	}

	if( m_InHeaders )
	{
		m_InHeaders = false;
		ProcessHeaders();
	}

	return DKIM_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////
// 
// ProcessHeaders - process the headers (to be implemented by derived class)
//
////////////////////////////////////////////////////////////////////////////////
int CDKIMBase::ProcessHeaders()
{
	return DKIM_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////
// 
// ProcessBody - process body line (to be implemented by derived class)
//
////////////////////////////////////////////////////////////////////////////////
int CDKIMBase::ProcessBody( char* szBuffer, int nBufLength )
{
	return DKIM_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////
// 
// RemoveSWSP - remove streaming white space from buffer/string inline
//
////////////////////////////////////////////////////////////////////////////////

struct isswsp
{
	bool operator()( char ch ) { return( ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' ); }
};

void CDKIMBase::RemoveSWSP( char* szBuffer )
{
	*remove_if( szBuffer, szBuffer+strlen(szBuffer), isswsp() ) = '\0';
}

void CDKIMBase::RemoveSWSP( char* pBuffer, int& nBufLength )
{
	nBufLength = remove_if( pBuffer, pBuffer+nBufLength, isswsp() ) - pBuffer;
}

void CDKIMBase::RemoveSWSP( string& sBuffer )
{
	sBuffer.erase( remove_if( sBuffer.begin(), sBuffer.end(), isswsp() ), sBuffer.end() );
}
