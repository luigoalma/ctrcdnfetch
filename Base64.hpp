#ifndef __BASE64_HPP__
#define __BASE64_HPP__
#include "types.h"

namespace Base64 {
	void Encode(const u8* data, size_t datalen, char*& out);
}

#endif