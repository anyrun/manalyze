/*
This file is part of Manalyze.

Manalyze is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Manalyze is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <string>
#include <vector>
#include <boost/cstdint.hpp>
#include <boost/system/api_config.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <hash-library/sha256.h>

#if defined BOOST_WINDOWS_API && !defined HASHLIB_API
	#ifdef HASHLIB_EXPORT
		#define HASHLIB_API    __declspec(dllexport)
	#else
		#define HASHLIB_API    __declspec(dllimport)
	#endif
#elif !defined BOOST_WINDOWS_API && !defined HASHLIB_API
	#define HASHLIB_API
#endif

namespace hash
{
	
/**
 *	@brief	Verifies that the input string is a valid bitcoin address.
 *	
 *	The input string is expected to be "clean" (i.e. no trailing spaces,
 *	was already matched by a regular expression, etc.).
 *	
 *	@param	address The address to test.
 *	
 *	@return	True if the input string a BTC address.
 */
HASHLIB_API bool test_btc_address(const std::string& address);

}