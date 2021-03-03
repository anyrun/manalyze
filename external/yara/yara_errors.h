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

#include <boost/assign.hpp>

#include "yara_wrapper.h"

namespace yara {

typedef std::map<int, std::string> error_dict;

extern const error_dict YARA_ERRORS;

/**
 *	@brief	Converts a Yara error code into an error message.
 *
 *	@return	An explanation of the error code if available of a string containing the 
 *			"Yara Error 0x[error code]" otherwise.
 */
std::string translate_error(int error_code);

} /* !namespace yara */