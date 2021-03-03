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

#include "hashes.h"

namespace hash {

const std::vector<pHash> ALL_DIGESTS = boost::assign::list_of
		(boost::static_pointer_cast<Hash>(boost::make_shared<MD5>()))
		(boost::static_pointer_cast<Hash>(boost::make_shared<SHA1>()))
		(boost::static_pointer_cast<Hash>(boost::make_shared<SHA256>()))
		(boost::static_pointer_cast<Hash>(boost::make_shared<Keccak>()));

pString hash_bytes(Hash& digest, const std::vector<boost::uint8_t>& bytes)
{
	digest.reset();
	if (bytes.size() > 0) {
		digest.add(&bytes[0], bytes.size());
	}
	return boost::make_shared<std::string>(digest.getHash());
}

// ----------------------------------------------------------------------------

const_shared_strings hash_bytes(const std::vector<pHash>& digests, const std::vector<boost::uint8_t>& bytes)
{
	shared_strings res = boost::make_shared<shared_strings::element_type>();
	for (auto it = digests.begin() ; it != digests.end() ; ++it)
	{
		(*it)->reset();
		if (bytes.size() > 0) {
			(*it)->add(&bytes[0], bytes.size());
		}
		res->push_back((*it)->getHash());
	}
	return res;
}

// ----------------------------------------------------------------------------

pString hash_file(Hash& digest, const std::string& filename)
{
	digest.reset();
	FILE* f = fopen(filename.c_str(), "rb");
	if (f == nullptr) {
		return pString();
	}
	auto buffer = boost::shared_array<boost::uint8_t>(new boost::uint8_t[1024]);
	int read = 0;
	while (1024 == (read = fread(buffer.get(), 1, 1024, f))) {
		digest.add(buffer.get(), read);
	}

	// Append the bytes of the last read operation
	if (read != 0) {
		digest.add(buffer.get(), read);
	}

	fclose(f);
	return boost::make_shared<std::string>(digest.getHash());
}

// ----------------------------------------------------------------------------

const_shared_strings hash_file(const std::vector<pHash>& digests, const std::string& filename)
{
	shared_strings res = boost::make_shared<shared_strings::element_type>();

	FILE* f = fopen(filename.c_str(), "rb");
	if (f == nullptr) {
		return boost::shared_ptr<shared_strings::element_type>();
	}

	for (std::vector<pHash>::const_iterator it = digests.begin() ; it != digests.end() ; ++it) {
		(*it)->reset();
	}

	auto buffer = boost::shared_array<boost::uint8_t>(new boost::uint8_t[1024]);
	int read = 0;
	while (1024 == (read = fread(buffer.get(), 1, 1024, f)))
	{
		for (auto it = digests.begin() ; it != digests.end() ; ++it) {
			(*it)->add(buffer.get(), read);
		}
	}

	for (auto it = digests.begin() ; it != digests.end() ; ++it)
	{
		// Append the bytes of the last read operation
		if (read != 0) {
			(*it)->add(buffer.get(), read);
		}
		res->push_back((*it)->getHash());
	}

	fclose(f);
	return res;
}


} // !namespace hash
