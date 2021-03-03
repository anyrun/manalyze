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
#include <stdio.h>

#include <boost/make_shared.hpp>
#include <boost/shared_array.hpp>
#include <boost/assign.hpp>
#include <boost/cstdint.hpp>
#include <boost/system/api_config.hpp>

#include "hash-library/hash.h"
#include "hash-library/md5.h"
#include "hash-library/sha1.h"
#include "hash-library/sha256.h"
#include "hash-library/keccak.h"

#if defined BOOST_WINDOWS_API && !defined HASHLIB_API
	#ifdef HASHLIB_EXPORT
		#define HASHLIB_API    __declspec(dllexport)
	#else
		#define HASHLIB_API    __declspec(dllimport)
	#endif
#elif !defined BOOST_WINDOWS_API && !defined HASHLIB_API
	#define HASHLIB_API
#endif

namespace hash {

typedef boost::shared_ptr<Hash> pHash;
typedef boost::shared_ptr<std::string> pString;
typedef boost::shared_ptr<std::vector<std::string> > shared_strings;
typedef boost::shared_ptr<const std::vector<std::string> > const_shared_strings;

/**
 *	@brief	Computes the hash of a buffer.
 *
 *	@param	Digest& digest The digest to use.
 *	@param	const std::vector<boost::uint8_t>& bytes The buffer to hash.
 *
 *	@return	A shared string containing the hash value. May be empty if an error occurred.
 */
HASHLIB_API pString hash_bytes(Hash& digest, const std::vector<boost::uint8_t>& bytes);

/**
 *	@brief	Computes the hash of a file.
 *
 *	@param	Digest& digest The digest to use.
 *	@param	const std::string& filename The path to the file to hash.
 *
 *	@return	A string containing the hash value. May be empty if an error occurred.
 */
HASHLIB_API pString hash_file(Hash& digest, const std::string& filename);

/**
 *	@brief	Computes the hashes of a file.
 *
 *	This function is used to calculate multiple hashes of the same file in a single pass.
 *
 *	@param	const std::vector<pDigest>& digests A list of digests to use.
 *			hash::ALL_DIGESTS is a suitable pre-initialized vector given for convenience.
 *
 *	@param	const std::string& filename The path to the file to hash.
 *
 *	@return	A shared vector containing all the computed hashes, in the same order as the input digests.
 *			If an error occurs for any digest, the return value's size is set to 0.
 */
HASHLIB_API const_shared_strings hash_file(const std::vector<pHash>& digests, const std::string& filename);

/**
 *	@brief	Computes the hashes of a buffer.
 *
 *	@param	const std::vector<pDigest>& digests A list of digests to use.
 *			hash::ALL_DIGESTS is a suitable pre-initialized vector given for convenience.
 *
 *	@param	const std::vector<boost::uint8_t>& bytes The buffer to hash.
 *
 *	@return	A shared vector containing all the computed hashes, in the same order as the input digests.
 *			If an error occurs for any digest, the return value's size is set to 0.
 */
HASHLIB_API const_shared_strings hash_bytes(const std::vector<pHash>& digests, const std::vector<boost::uint8_t>& bytes);

// Helper vector containing all available digests.
extern HASHLIB_API const std::vector<pHash> ALL_DIGESTS;

// Helper #defines to access ALL_DIGESTS ciphers in a readable manner.
#define ALL_DIGESTS_MD5		0
#define ALL_DIGESTS_SHA1	1
#define ALL_DIGESTS_SHA256	2
#define ALL_DIGESTS_SHA3	3

} // !namespace hash