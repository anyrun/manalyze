cmake_minimum_required (VERSION 2.6)
project (hash-library)

add_library(hash-library SHARED crc32.cpp keccak.cpp md5.cpp sha1.cpp sha256.cpp fuzzy.cpp edit_dist.cpp ssdeep.cpp hashes.cpp bitcoin.cpp)
if (WIN32)
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
			set_target_properties(hash-library PROPERTIES COMPILE_DEFINITIONS "HASHLIB_EXPORT")
else()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        add_definitions(-fPIC)
    endif()
endif()

# make install command for linux machines:
if ("${CMAKE_SYSTEM}" MATCHES "Linux")
	# Copy binaries
	install(TARGETS hash-library
			RUNTIME DESTINATION /usr/local/bin
			LIBRARY DESTINATION /usr/local/lib
			ARCHIVE DESTINATION /usr/local/lib/static)

    # Run ldconfig.
	execute_process(COMMAND ldconfig)
endif()
