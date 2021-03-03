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

#include "yara_wrapper.h"

namespace yara
{

int Yara::_instance_count = 0;

Yara::Yara()
{
	_compiler = nullptr;
	_rules = nullptr;
	_current_rules = "";

	if (_instance_count == 0) {
		yr_initialize();
	}
	++_instance_count;
}

// ----------------------------------------------------------------------------

Yara::~Yara()
{
	_clean_compiler_and_rules();

	--_instance_count;
	if (_instance_count == 0) {
		yr_finalize();
	}
}

// ----------------------------------------------------------------------------

pYara Yara::create() {
	return boost::make_shared<Yara>();
}

// ----------------------------------------------------------------------------

void* Yara::operator new(size_t size)
{
	void* p = malloc(size);
	if (p == nullptr)
		throw std::bad_alloc();
	return p;
}

// ----------------------------------------------------------------------------

void Yara::operator delete(void* p)
{
	if (p != nullptr) {
		free(p);
	}
}

// ----------------------------------------------------------------------------

void Yara::_clean_compiler_and_rules() const
{
	if (_compiler != nullptr) {
		yr_compiler_destroy(_compiler);
	}
	if (_rules != nullptr) {
		yr_rules_destroy(_rules);
	}
}

// ----------------------------------------------------------------------------

bool Yara::load_rules(const std::string& rule_filename)
{
	if (_current_rules == rule_filename) {
		return true;
	}
	else { // The previous rules and compiler have to be freed manually.
		_clean_compiler_and_rules();
	}

	bool res = false;
	int retval;

	// Look for a compiled version of the rule file first.
	if (boost::filesystem::exists(rule_filename + "c")) { // File extension is .yarac instead of .yara.
		retval = yr_rules_load((rule_filename + "c").c_str(), &_rules);
	}
	else {
		retval = yr_rules_load(rule_filename.c_str(), &_rules);
	}

	// Yara rules compiled with a previous Yara version. Delete and recompile.
	if (retval == ERROR_UNSUPPORTED_FILE_VERSION) {
		boost::filesystem::remove(rule_filename + "c");
	}

	if (retval != ERROR_SUCCESS && retval != ERROR_INVALID_FILE && retval != ERROR_UNSUPPORTED_FILE_VERSION)
	{
		PRINT_ERROR << "Could not load yara rules (" << translate_error(retval) << ")." << std::endl;
		return false;
	}

	if (retval == ERROR_SUCCESS) {
		return true;
	}
	else if (retval == ERROR_INVALID_FILE || retval == ERROR_UNSUPPORTED_FILE_VERSION) // Uncompiled rules
	{
		if (yr_compiler_create(&_compiler) != ERROR_SUCCESS) {
			return false;
		}
		yr_compiler_set_callback(_compiler, compiler_callback, nullptr);
		FILE* rule_file = fopen(rule_filename.c_str(), "r");
		if (rule_file == nullptr) {
			return false;
		}
		retval = yr_compiler_add_file(_compiler, rule_file, nullptr, rule_filename.c_str());
		if (retval != 0)
		{
			PRINT_ERROR << "Could not compile yara rules (" << retval << " error(s))." << std::endl;
			goto END;
		}
		retval = yr_compiler_get_rules(_compiler, &_rules);
		if (retval != ERROR_SUCCESS) {
			goto END;
		}

		// Save the compiled rules to improve load times.
		// /!\ The compiled rules will have to be deleted if the original (readable) rule file is updated!
		// TODO: Compare timestamps and recompile automatically.
		retval = yr_rules_save(_rules, (rule_filename + "c").c_str());
		if (retval != ERROR_SUCCESS) {
			goto END;
		}

		res = true;
		_current_rules = rule_filename;
		END:
		if (rule_file != nullptr) {
			fclose(rule_file);
		}
	}
	return res;
}

// ----------------------------------------------------------------------------

const_matches Yara::scan_bytes(const std::vector<boost::uint8_t>& bytes) const
{
	pcallback_data cb_data(new callback_data);
	cb_data->yara_matches = boost::make_shared<match_vector>();
	int retval;
	if (_rules == nullptr || bytes.size() == 0)
	{
		if (_rules == nullptr) {
			PRINT_ERROR << "No Yara rules loaded!" << std::endl;
		}
		return cb_data->yara_matches;
	}

	// Make a copy of the input buffer, because we can't be sure that Yara will not modify it
	// and the constness of the input has to be guaranteed.
	std::vector<boost::uint8_t> copy(bytes.begin(), bytes.end());

	// Yara setup done. Scan the file.
	retval = yr_rules_scan_mem(_rules,
							   &copy[0],		// The bytes to scan
							   bytes.size(),	// Number of bytes
                               SCAN_FLAGS_PROCESS_MEMORY,
							   get_match_data,
							   &cb_data,			// The vector to fill
							   0);				// No timeout)

	if (retval != ERROR_SUCCESS)
	{
		PRINT_ERROR << "Yara error: " << translate_error(retval) << std::endl;
		cb_data->yara_matches->clear();
	}

	return cb_data->yara_matches;
}

// ----------------------------------------------------------------------------

const_matches Yara::scan_file(const std::string& path, pmanape_data pe_data) const
{
	pcallback_data cb_data(new callback_data);
	cb_data->yara_matches = boost::make_shared<match_vector>();
	cb_data->pe_info = pe_data;
	int retval;
	if (_rules == nullptr)
	{
		PRINT_ERROR << "No Yara rules loaded!" << std::endl;
		return cb_data->yara_matches;
	}

	retval = yr_rules_scan_file(_rules,
						        path.c_str(),
                                SCAN_FLAGS_PROCESS_MEMORY,
								get_match_data,
								&cb_data,
								0);

	if (retval != ERROR_SUCCESS)
	{
		PRINT_ERROR << "Yara error: " << translate_error(retval) << std::endl;
		cb_data->yara_matches->clear();
	}
	return cb_data->yara_matches;
}

// ----------------------------------------------------------------------------

void compiler_callback(int error_level, const char* file_name, int line_number, const char* message, void* user_data)
{
	if (error_level == YARA_ERROR_LEVEL_ERROR)
	{
		PRINT_ERROR << "[Yara compiler] " << (file_name != nullptr ? file_name : "") << "(" << line_number
			<< ") : " << message << std::endl;
	}
	#ifdef _DEBUG // Warnings are very verbose, do not display them unless this is a debug release.
		if (error_level == YARA_ERROR_LEVEL_WARNING)
		{
			PRINT_WARNING << "[Yara compiler] " << (file_name != nullptr ? file_name : "") << "("
				<< line_number << ") : " << message << std::endl;
		}
	#endif // _DEBUG
}

// ----------------------------------------------------------------------------

int get_match_data(int message, void* message_data, void* data)
{
	matches target;
	YR_META* meta;
	YR_STRING* s;
	YR_RULE* rule;
	pMatch m;
	YR_MODULE_IMPORT* mi; // Used for the CALLBACK_MSG_IMPORT_MODULE message.
	pcallback_data* cb_data = (pcallback_data*) data;
	if (!cb_data)
	{
		PRINT_ERROR << "Yara wrapper callback called with no data!" << std::endl;
		return ERROR_CALLBACK_ERROR;
	}

	switch (message)
	{
		case CALLBACK_MSG_RULE_MATCHING:
			rule = (YR_RULE*) message_data;
			target = cb_data->get()->yara_matches;
			meta = rule->metas;
			s = rule->strings;
			m = boost::make_shared<Match>();

			while (!META_IS_NULL(meta))
			{
				m->add_metadata(std::string(meta->identifier), meta->string);
				++meta;
			}
			while (!STRING_IS_NULL(s))
			{
				if (STRING_FOUND(s))
				{
					YR_MATCH* match = STRING_MATCHES(s).head;
					while (match != nullptr)
					{
						if (!STRING_IS_HEX(s))
						{
							std::string found((char*) match->data, match->data_length);
							// Yara inserts null bytes when it matches unicode strings. Dirty fix to remove them all.
							found.erase(std::remove(found.begin(), found.end(), '\0'), found.end());
							m->add_found_string(found);
						}
						else
						{
							std::stringstream ss;
							ss << std::hex;
							for (int i = 0; i < std::min(20, match->data_length); i++) {
								ss << static_cast<unsigned int>(match->data[i]) << " "; // Don't interpret as a char
							}
							if (match->data_length > 20) {
								ss << "...";
							}
							m->add_found_string(ss.str());
						}
						match = match->next;
					}
				}
				++s;
			}

			target->push_back(m);
			return CALLBACK_CONTINUE; // Don't stop on the first matching rule.

		case CALLBACK_MSG_RULE_NOT_MATCHING:
		case CALLBACK_MSG_MODULE_IMPORTED:
			return CALLBACK_CONTINUE;

		// Detect when the ManaPE module is loaded
		case CALLBACK_MSG_IMPORT_MODULE:
			mi = (YR_MODULE_IMPORT*) message_data;
			if (std::string(mi->module_name) == "manape")
			{
				if (!cb_data || cb_data->get()->pe_info == nullptr)
				{
					PRINT_ERROR << "Yara rule imports the ManaPE module, but no ManaPE data was given!" << std::endl;
					return ERROR_CALLBACK_ERROR;
				}
				else if (!cb_data)
				{
					PRINT_ERROR << "No data given to the callback to store results!" << std::endl;
					return ERROR_CALLBACK_ERROR;
				}
				mi->module_data = &*(cb_data->get()->pe_info);
			}
			return ERROR_SUCCESS;

		case CALLBACK_MSG_SCAN_FINISHED:
			return ERROR_SUCCESS;

		default:
			PRINT_WARNING << "Yara callback received an unhandled message (" << message << ")." << std::endl;
			return ERROR_SUCCESS;
	}
}

} // !namespace yara
