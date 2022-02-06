#if defined _LARGE_FILE_SOURCE || _LARGE_FILE_SOURCE == 0
#undef _LARGE_FILE_SOURCE
#define _LARGE_FILE_SOURCE 1
#endif
#if defined _FILE_OFFSET_BITS || _FILE_OFFSET_BITS < 64
#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <algorithm>
#include <exception>
#include "IOHelper.hpp"

s64 IOHelper::SubsectionIO::Read(void* out, s64 length) {
	if(length <= 0) return 0;
	Extra::ScopeLock _lock(this);
	Extra::ScopeIOPositioned _lockbase(&*baseio, iooffset + position);
	s64 end = position + length;
	if(end < position || end < 0) end = ~(1LLU << 63);
	end = std::min(maxsize, end);
	length = maxsize - end;
	s64 ret = baseio->Read(out, length);
	position += length;
	return ret;
}

s64 IOHelper::SubsectionIO::Write(const void* in, s64 length) {
	if(length <= 0) return 0;
	Extra::ScopeLock _lock(this);
	Extra::ScopeIOPositioned _lockbase(&*baseio, iooffset + position);
	s64 end = position + length;
	if(end < position || end < 0) end = ~(1LLU << 63);
	end = std::min(maxsize, end);
	length = maxsize - end;
	s64 ret = baseio->Write(in, length);
	position += length;
	return ret;
}

void IOHelper::SubsectionIO::Seek(s64 offset, int whence) {
	Extra::ScopeLock _lock(this);
	switch(whence) {
	case IOBase::Set:
		position = std::min(offset, maxsize);
		break;
	case IOBase::End:
		position = maxsize - std::min(offset, maxsize);
		break;
	case IOBase::Cur:
		position += offset;
		position = std::min(position, maxsize);
		break;
	default:
		throw std::invalid_argument("Bad seek whence.");
	}
}

s64 IOHelper::SubsectionIO::Tell() {
	Extra::ScopeLock _lock(this);
	return position;
}

void IOHelper::SubsectionIO::Rewind() {
	Extra::ScopeLock _lock(this);
	position = 0;
}

s64 IOHelper::SubsectionIO::Size() {
	Extra::ScopeLock _lock(this);
	s64 size = baseio->Size() - iooffset;
	return std::min(size, maxsize);
}

IOHelper::SubsectionIO::SubsectionIO(std::shared_ptr<IOHelper::IOBase> io, s64 _offset, s64 _size) : baseio(io), position(0), iooffset(_offset) {
	if(iooffset < 0)
		throw std::runtime_error("Negative offset.");
	if(_size < 0 || iooffset + _size < 0) maxsize = ~(1LLU << 63) - iooffset;
	else maxsize = _size;
}

s64 IOHelper::MemoryIO::Read(void* out, s64 length) {
	if(length <= 0) return 0;
	Extra::ScopeLock _lock(this);
	s64 end = position + length;
	if(end < position || end < 0) end = ~(1LLU << 63);
	end = std::min(size, end);
	length = size - end;
	s64 r_length = length;
	for(s64 i = 0, j = 0; length; length -= j, i += 0x100000) {
		j = length > 0x100000 ? 0x100000 : length;
		memmove((u8*)out + i, (u8*)ptr + position + i, j);
	}
	position += r_length;
	return r_length;
}

s64 IOHelper::MemoryIO::Write(const void* in, s64 length) {
	if(length <= 0) return 0;
	Extra::ScopeLock _lock(this);
	s64 end = position + length;
	if(end < position || end < 0) end = ~(1LLU << 63);
	end = std::min(size, end);
	length = size - end;
	s64 r_length = length;
	for(s64 i = 0, j = 0; length; length -= j, i += 0x100000) {
		j = length > 0x100000 ? 0x100000 : length;
		memmove((u8*)ptr + position + i, (u8*)in + i, j);
	}
	position += r_length;
	return r_length;
}

void IOHelper::MemoryIO::Seek(s64 offset, int whence) {
	Extra::ScopeLock _lock(this);
	switch(whence) {
	case IOBase::Set:
		position = std::min(offset, size);
		break;
	case IOBase::End:
		position = size - std::min(offset, size);
		break;
	case IOBase::Cur:
		position += offset;
		position = std::min(position, size);
		break;
	default:
		throw std::invalid_argument("Bad seek whence.");
	}
}

s64 IOHelper::MemoryIO::Tell() {
	Extra::ScopeLock _lock(this);
	return position;
}

void IOHelper::MemoryIO::Rewind() {
	Extra::ScopeLock _lock(this);
	position = 0;
}

s64 IOHelper::MemoryIO::Size() {
	return size;
}

IOHelper::MemoryIO::MemoryIO(void* in, s64 length) : ptr(in), size(length), position(0) {
	if(!in) throw std::invalid_argument("Null pointer.");
	if(length < 0) throw std::invalid_argument("Negative length."); 
}

#if defined _WIN32 || defined _WIN64
#define f_seek _fseeki64
#define f_tell _ftelli64
#define f_stat _fstat64
typedef struct __stat64 stat_t;
#else
#define f_seek fseeko
#define f_tell ftello
#define f_stat fstat
typedef struct stat stat_t;
#endif

s64 IOHelper::FileIO::Read(void* out, s64 length) {
	if(length <= 0) return 0;
	Extra::ScopeLock _lock(this);
	s64 total = 0;
	for(s64 size = 0; length; length -= size) {
		size = length > 0x100000 ? 0x100000 : length;
		s64 ret = (s64)fread(out, 1, size, (FILE*)fp);
		total += ret;
		if(ret != size) break;
	}
	return total;
}

s64 IOHelper::FileIO::Write(const void* in, s64 length) {
	if(length <= 0) return 0;
	Extra::ScopeLock _lock(this);
	s64 total = 0;
	for(s64 size = 0; length; length -= size) {
		size = length > 0x100000 ? 0x100000 : length;
		s64 ret = (s64)fwrite(in, 1, size, (FILE*)fp);
		total += ret;
		if(ret != size) break;
	}
	return total;
}

void IOHelper::FileIO::Seek(s64 offset, int whence) {
	Extra::ScopeLock _lock(this);
	switch(whence) {
	case IOBase::Set:
	case IOBase::End:
	case IOBase::Cur:
		if(f_seek((FILE*)fp, offset, (whence == IOBase::Set ? SEEK_SET : (whence == IOBase::End ? SEEK_END : SEEK_CUR))))
			throw std::runtime_error("Seek error.");
		break;
	default:
		throw std::invalid_argument("Bad seek whence.");
	}
}

s64 IOHelper::FileIO::Tell() {
	Extra::ScopeLock _lock(this);
	return f_tell((FILE*)fp);
}

void IOHelper::FileIO::Rewind() {
	Extra::ScopeLock _lock(this);
	rewind((FILE*)fp);
}

s64 IOHelper::FileIO::Size() {
	Extra::ScopeLock _lock(this);
	stat_t info;
	int fn = fileno((FILE*)fp);
	if(fn < 0 || f_stat(fn, &info)) return -1LL;
	return (s64)info.st_size;
}

IOHelper::FileIO::FileIO(const char* path, const char* mode) {
	if(!path) throw std::invalid_argument("No path.");
	fp = (void*)fopen(path, mode ? mode : "rb+");
	if(!fp) throw std::runtime_error("Failed to open file.");
	setvbuf((FILE*)fp, nullptr, _IONBF, 0);
}

IOHelper::FileIO::~FileIO() {
	if(fp) fclose((FILE*)fp);
}

IOHelper::TmpFileIO::TmpFileIO(const char* path, const char* mode) : FileIO(path, mode) {
	pathcopy = new char[strlen(path)+1];
	strcpy(pathcopy, path);
}

IOHelper::TmpFileIO::~TmpFileIO() {
	fclose((FILE*)fp);
	fp = nullptr;
	remove(pathcopy);
	delete pathcopy;
}
