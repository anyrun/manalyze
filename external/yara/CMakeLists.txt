cmake_minimum_required (VERSION 2.6)
project (yara)
find_package (Threads)

add_library(yara SHARED yara_wrapper.cpp yara_errors.cpp ahocorasick.c arena.c atoms.c compiler.c exec.c exefiles.c filemap.c grammar.c hash.c hex_grammar.c hex_lexer.c lexer.c libyara.c mem.c modules.c object.c parser.c proc.c re.c re_grammar.c re_lexer.c rules.c scan.c sizedstr.c stream.c strutils.c threading.c endian.c
	                modules/manape.c)
target_link_libraries (yara manacommons ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES})

include_directories(${PROJECT_SOURCE_DIR}
					${PROJECT_SOURCE_DIR}/include
					${PROJECT_SOURCE_DIR}/libyara)

if (WIN32)
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
			set_target_properties(yara PROPERTIES COMPILE_DEFINITIONS "YARA_EXPORT")
else()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        add_definitions(-fPIC)
    endif()
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
endif()

# make install command for linux machines:
if ("${CMAKE_SYSTEM}" MATCHES "Linux")
	# Copy binaries
	install(TARGETS yara
			RUNTIME DESTINATION /usr/local/bin
			LIBRARY DESTINATION /usr/local/lib
			ARCHIVE DESTINATION /usr/local/lib/static)

	# Run ldconfig.
	execute_process(COMMAND ldconfig)
endif()
