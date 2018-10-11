#include <exception>
#include <stdexcept>
#include <new>
#include <vector>

namespace Utils {
	namespace DirectoryManagement {
		class DirFileList {
		public:
			class entry {
			public:
				char* name;
				int type; //0 folder, 1 file, 2 unknown or special types, -1 no entry.
				entry& operator=(entry& other) {
					if(this == &other) {
						char* tmpname = (char*)calloc(strlen(other.name)+1, 1);
						if(!tmpname) throw std::bad_alloc();
						free(name);
						name = tmpname;
						type = other.type;
					}
					return *this
				}
				entry() : name(NULL), type(-1) {}
				entry(entry& other) : entry() {*this = other;}
				~entry() {free(name);}
			};
		private:
			std::vector<entry*> entries;
			void Clear() {
				for(size_t i = 0; i < entries.size(); i++)
					delete entries[i];
				entries.clear();
			}
		public:
			const entry& operator[](int index) const {
				return *(entries.at(index));
			}
			DirFileList& operator=(DirFileList& other) {
				if(this != &other) {
					Clear();
					for(size_t i = 0; i < other.entries.size(); i++) {
						entry* foo = nullptr;
						try {
							foo = new entry(*entries[i]);
							entries.push_back(nullptr);
							entries[i] = foo;
						} catch(...) {
							Clear();
							delete foo;
							throw;
						}
					}
				}
				return *this;
			}
			DirFileList() {}
			DirFileList(DirFileList& other) {*this = other;}
			~DirFileList() {Clear();}
			friend int DirectoryListing(DirFileList& output, const char* path) noexcept;
		};

		int MakeDirectory(const char* path, bool recursive = true);
		int DirectoryListing(DirFileList& output, const char* path) noexcept;
		int CheckIfDir(const char* path) noexcept;
	}
}
