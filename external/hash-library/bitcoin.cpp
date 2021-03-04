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

#include "bitcoin.h"

namespace hash {

bool test_btc_address(const std::string& address)
{
	std::string base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	std::vector<boost::uint8_t> data(25);
	boost::multiprecision::cpp_int big_int = 0;

	// Decode base58 data.
	for (char c : address) {
		big_int = big_int * 58 + base58.find_first_of(c);
	}
	for (int i = 24; i >= 0; --i)
	{
		// Safe because of the & 0xFF.
		data[24 - i] = boost::multiprecision::cpp_int((big_int >> i * 8) & 0xFF).convert_to<boost::uint8_t>();
	}

	// Compute the checksum.
	// A BTC addess has the following structure: [21 bytes of data][first 4 bytes of sha256(sha256(data))]
	SHA256 sha256;
	boost::uint8_t sha_result[32];
	sha256.add(&data[0], 21); // The 4 last bytes contain the checksum
	sha256.getHash(sha_result);
	sha256.reset();
	sha256.add(sha_result, 32);
	sha256.getHash(sha_result);

	// Compare the checksums (4 bytes)
	return memcmp(sha_result, &data[21], 4) == 0;
}

} // !namespace hash