#include <cstdlib>
#include <exception>
#include <stdexcept>
#include <new>
#include <openssl/evp.h>
#include "Base64.hpp"

void Base64::Encode(const u8* data, size_t datalen, char*& out) {
	int encodedlen = 4 * ((datalen + 2) / 3);
	out = (char*)calloc(encodedlen+1,1);
	if(!out) throw std::bad_alloc();
	if(EVP_EncodeBlock((u8*)out, data, datalen) != encodedlen) {
		free(out);
		out = NULL;
		throw std::runtime_error("Error at base64 encoding.");
	}
}
