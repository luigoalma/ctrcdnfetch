#ifndef __SHAREDSTORAGE_HPP__
#define __SHAREDSTORAGE_HPP__

namespace NintendoData {
	namespace SharedStorage {
		int Load(FILE*& out, const char* file) noexcept;
		int Save(const void* in, size_t inlen, const char* file) noexcept;
	}
}

#endif
