// //////////////////////////////////////////////////////////
// digest.h
// Copyright (c) 2014 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once

#include <string>

class Digest
{
public:
	virtual std::string getHash() = 0;
	virtual void add(const void* data, size_t numBytes) = 0;
	virtual void reset() = 0;
};