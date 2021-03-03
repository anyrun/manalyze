// //////////////////////////////////////////////////////////
// hash.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once

#if (defined(__unix__) || defined(unix)) && !defined(USG)
#include <sys/param.h>
#endif

#include <string>
#define HASH_LIBRARY_VERSION 7

/// abstract base class
class Hash
{
public:
  /// compute hash of a memory block
  virtual std::string operator()(const void* data, size_t numBytes) = 0;
  /// compute hash of a string, excluding final zero
  virtual std::string operator()(const std::string& text) = 0;

  /// add arbitrary number of bytes
  virtual void add(const void* data, size_t numBytes) = 0;

  /// return latest hash as hex characters
  virtual std::string getHash() = 0;

  /// restart
  virtual void reset() = 0;
};
