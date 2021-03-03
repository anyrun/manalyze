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

#include <stdint.h>

/**
 *	@brief	Some summary section information.
 */
typedef struct manape_file_portion_t {
	uint32_t	start;
	uint32_t	size;
} manape_file_portion;

/**
	The object which is passed to the Yara ManaPE module.
*/
typedef struct manape_data_t {
	uint32_t				entrypoint;
	manape_file_portion*	sections;
	uint32_t				number_of_sections;
	manape_file_portion		version_info;
} manape_data;
