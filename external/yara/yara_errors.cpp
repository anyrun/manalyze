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

#include "yara_errors.h"

namespace yara {

/*
 * Generate these with the following command when they are updated:
 *  cat error.h | perl -ne '/#define ([^ ]+)[ \t]*([0-9]+)/ && print "(" . $2 . ",\t\"" . $1 . "\")\n"'
 */
const error_dict YARA_ERRORS =
	boost::assign::map_list_of	(1,		"ERROR_INSUFICIENT_MEMORY")
								(2,		"ERROR_COULD_NOT_ATTACH_TO_PROCESS")
								(3,		"ERROR_COULD_NOT_OPEN_FILE")
								(4,		"ERROR_COULD_NOT_MAP_FILE")
								(6,		"ERROR_INVALID_FILE")
								(7,		"ERROR_CORRUPT_FILE")
								(8,		"ERROR_UNSUPPORTED_FILE_VERSION")
								(9,		"ERROR_INVALID_REGULAR_EXPRESSION")
								(10,	"ERROR_INVALID_HEX_STRING")
								(11,	"ERROR_SYNTAX_ERROR")
								(12,	"ERROR_LOOP_NESTING_LIMIT_EXCEEDED")
								(13,	"ERROR_DUPLICATED_LOOP_IDENTIFIER")
								(14,	"ERROR_DUPLICATED_IDENTIFIER")
								(15,	"ERROR_DUPLICATED_TAG_IDENTIFIER")
								(16,	"ERROR_DUPLICATED_META_IDENTIFIER")
								(17,	"ERROR_DUPLICATED_STRING_IDENTIFIER")
								(18,	"ERROR_UNREFERENCED_STRING")
								(19,	"ERROR_UNDEFINED_STRING")
								(20,	"ERROR_UNDEFINED_IDENTIFIER")
								(21,	"ERROR_MISPLACED_ANONYMOUS_STRING")
								(22,	"ERROR_INCLUDES_CIRCULAR_REFERENCE")
								(23,	"ERROR_INCLUDE_DEPTH_EXCEEDED")
								(24,	"ERROR_WRONG_TYPE")
								(25,	"ERROR_EXEC_STACK_OVERFLOW")
								(26,	"ERROR_SCAN_TIMEOUT")
								(27,	"ERROR_TOO_MANY_SCAN_THREADS")
								(28,	"ERROR_CALLBACK_ERROR")
								(29,	"ERROR_INVALID_ARGUMENT")
								(30,	"ERROR_TOO_MANY_MATCHES")
								(31,	"ERROR_INTERNAL_FATAL_ERROR")
								(32,	"ERROR_NESTED_FOR_OF_LOOP")
								(33,	"ERROR_INVALID_FIELD_NAME")
								(34,	"ERROR_UNKNOWN_MODULE")
								(35,	"ERROR_NOT_A_STRUCTURE")
								(36,	"ERROR_NOT_INDEXABLE")
								(37,	"ERROR_NOT_A_FUNCTION")
								(38,	"ERROR_INVALID_FORMAT")
								(39,	"ERROR_TOO_MANY_ARGUMENTS")
								(40,	"ERROR_WRONG_ARGUMENTS")
								(41,	"ERROR_WRONG_RETURN_TYPE")
								(42,	"ERROR_DUPLICATED_STRUCTURE_MEMBER")
								(43,	"ERROR_EMPTY_STRING")
								(44,	"ERROR_DIVISION_BY_ZERO")
								(45,	"ERROR_REGULAR_EXPRESSION_TOO_LARGE")
								(46,	"ERROR_TOO_MANY_RE_FIBERS")
								(47,    "ERROR_COULD_NOT_READ_PROCESS_MEMORY")
								(48, 	"ERROR_INVALID_EXTERNAL_VARIABLE_TYPE")
								(49, 	"ERROR_REGULAR_EXPRESSION_TOO_COMPLEX")
								(50, 	"ERROR_INVALID_MODULE_NAME");

std::string translate_error(int error_code)
{
	if (YARA_ERRORS.find(error_code) != YARA_ERRORS.end()) {
		return YARA_ERRORS.at(error_code);
	}
	else
	{
		std::stringstream ss;
		ss << "Yara Error 0x" << std::hex << error_code;
		return ss.str();
	}
}

}
