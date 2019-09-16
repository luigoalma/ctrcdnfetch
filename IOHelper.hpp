#pragma once
#include <mutex>
#include <memory>
#include "types.h"

namespace IOHelper {
	namespace Extra {
		class ScopeLock;
		class ScopeIOPositioned;
	}
	class IOBase {
	protected:
		std::recursive_mutex lock;
		void Lock() {lock.lock();}
		void Unlock() {lock.unlock();}
	public:
		enum Seekdir {
			Set = 0,
			End,
			Cur
		};
		virtual s64 Read(void*, s64) = 0;
		virtual s64 Write(const void*, s64) = 0;
		virtual void Seek(s64, int) = 0;
		virtual s64 Tell() = 0;
		virtual void Rewind() = 0;
		virtual s64 Size() = 0;
		virtual ~IOBase() {}
		friend class Extra::ScopeLock;
		friend class Extra::ScopeIOPositioned;
	};

	class SubsectionIO : public IOBase {
	protected:
		std::shared_ptr<IOBase> baseio;
		s64 position;
		s64 iooffset;
		s64 maxsize;
	public:
		virtual s64 Read(void* out, s64 length);
		virtual s64 Write(const void* in, s64 length);
		virtual void Seek(s64 offset, int whence);
		virtual s64 Tell();
		virtual void Rewind();
		virtual s64 Size();
		SubsectionIO(std::shared_ptr<IOBase> io, s64 _offset, s64 _size);
		virtual ~SubsectionIO() {}
	private:
		SubsectionIO() {}
	};

	class MemoryIO : public IOBase {
	protected:
		void* ptr;
		s64 size;
		s64 position;
	public:
		virtual s64 Read(void* out, s64 length);
		virtual s64 Write(const void* in, s64 length);
		virtual void Seek(s64 offset, int whence);
		virtual s64 Tell();
		virtual void Rewind();
		virtual s64 Size();
		MemoryIO(void* in, s64 length);
	};

	class FileIO : public IOBase {
	protected:
		void* fp;
	public:
		virtual s64 Read(void* out, s64 length);
		virtual s64 Write(const void* in, s64 length);
		virtual void Seek(s64 offset, int whence);
		virtual s64 Tell();
		virtual void Rewind();
		virtual s64 Size();
		FileIO(const char* path, const char* mode = nullptr);
		virtual ~FileIO();
	};

	class TmpFileIO : public FileIO {
	protected:
		char* pathcopy;
	public:
		TmpFileIO(const char* path, const char* mode = nullptr);
		virtual ~TmpFileIO();
	};

	namespace Extra {
		class ScopeLock {
			IOBase* locker;
		public:
			inline ScopeLock(IOBase* o) : locker(o) {locker->Lock();}
			inline ~ScopeLock() {locker->Unlock();}
		};
		class ScopeIOPositioned {
			IOBase* io;
			s64 saved_position;
		public:
			inline ScopeIOPositioned(IOBase* o, s64 new_absolute_pos) : io(o) {
				io->Lock();
				saved_position = io->Tell();
				io->Seek(new_absolute_pos, IOBase::Set);
			}
			inline ~ScopeIOPositioned() {
				io->Seek(saved_position, IOBase::Set);
				io->Unlock();
			}
		};
	}
}
