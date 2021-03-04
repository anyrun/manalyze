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

#include <yara/modules/manape_data.h>
#include <yara/modules.h>


/**
 *	@brief	This module is a replacement for Yara's PE module. Manalyze already does all the PE parsing, so there
 *			is little point in bundling another PE parser. This module acts as a gateway between Yara and the data
 *			already parsed by Manalyze.
 */
#define MODULE_NAME manape


begin_declarations;

declare_integer("ep");
declare_integer("num_sections")
begin_struct_array("sections");
	declare_integer("start");
	declare_integer("size");
end_struct_array("sections");
begin_struct("version_info")
	declare_integer("start");
	declare_integer("size");
end_struct("version_info")

end_declarations;

int module_initialize(
	YR_MODULE* module)
{
	return ERROR_SUCCESS;
}

int module_finalize(
	YR_MODULE* module)
{
	return ERROR_SUCCESS;
}

int module_load(
	YR_SCAN_CONTEXT* context,
	YR_OBJECT* module_object,
	void* module_data,
	size_t module_data_size)
{
	uint32_t i;

	if (module_data == NULL) {
		return ERROR_INVALID_ARGUMENT;
	}
	manape_data* pe_info = (manape_data*) module_data;
	set_integer(pe_info->entrypoint, module_object, "ep");
	set_integer(pe_info->number_of_sections, module_object, "num_sections");
	for (i = 0 ; i < pe_info->number_of_sections ; ++i)
	{
		set_integer(pe_info->sections[i].start, module_object, "sections[%i].start", i);
		set_integer(pe_info->sections[i].size, module_object, "sections[%i].size", i);
	}
	set_integer(pe_info->version_info.start, module_object, "version_info.start");
	set_integer(pe_info->version_info.size, module_object, "version_info.size");
	return ERROR_SUCCESS;
}

int module_unload(
	YR_OBJECT* module_object)
{
	return ERROR_SUCCESS;
}

#undef MODULE_NAME
