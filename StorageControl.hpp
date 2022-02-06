#ifndef __STORAGECONTROL_HPP__
#define __STORAGECONTROL_HPP__
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <cstdio>

namespace NintendoData {
	namespace SharedStorage {
		int Load(FILE*& out, const char* file);
		int Save(const void* in, size_t inlen, const char* file);
	}
	class TemporaryStorage {
	private:
		char* ContainerPath;
		//non copyable but moveable
		TemporaryStorage& operator=(const TemporaryStorage&);
		TemporaryStorage(const TemporaryStorage&);
	public:
		const char* GetPath() {return ContainerPath;}
		TemporaryStorage& operator=(TemporaryStorage&& other) {
			if(this != &other) {
				this->~TemporaryStorage();
				ContainerPath = other.ContainerPath;
				other.ContainerPath = nullptr;
			}
			return *this;
		}
		TemporaryStorage(TemporaryStorage&& other) {*this = other;}
		TemporaryStorage();
		~TemporaryStorage();
	};
}

#endif
