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

#include <iostream>
#include <vector>
#include <boost/shared_array.hpp>
#include <boost/make_shared.hpp>
#include <boost/cstdint.hpp>
#include <boost/system/api_config.hpp>

#include "hash.h"
#include "fuzzy.h"

#if defined BOOST_WINDOWS_API && !defined HASHLIB_API
	#ifdef HASHLIB_EXPORT
		#define HASHLIB_API    __declspec(dllexport)
	#else
		#define HASHLIB_API    __declspec(dllimport)
	#endif
#elif !defined BOOST_WINDOWS_API && !defined HASHLIB_API
	#define HASHLIB_API
#endif

namespace ssdeep {

typedef boost::shared_ptr<std::string> pString;

/**
*	@brief	Calculates the SSDeep hash of a file based on its name.
*
*	@param	const std::string& filename The path to the file to hash.
*
*	@return	A shared string containing the SSDeep hash. Empty if an error occurs.
*/
HASHLIB_API pString hash_file(const std::string& filename);

/**
*	@brief	Calculates the SSDeep hash of given bytes.
*
*	@param	const std::vector<boost::uint8_t>& bytes The bytes to hash.
*
*	@return	A shared string containing the SSDeep hash. Empty if an error occurs.
*/
HASHLIB_API pString hash_buffer(const std::vector<boost::uint8_t>& bytes);

}
