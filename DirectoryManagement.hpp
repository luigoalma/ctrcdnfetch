#ifndef __DIRECTORYMANAGEMENT_HPP__
#define __DIRECTORYMANAGEMENT_HPP__
#include <exception>
#include <stdexcept>
#include <new>
#include <vector>
#include <string>

namespace Utils {
	namespace DirectoryManagement {
		class DirFileList {
		public:
			class entry {
			private:
				char* name;
				int type; //0 folder, 1 file, 2 unknown or special types, -1 no entry.
			public:
				const char* GetName() const {return name;}
				int GetType() const {return type;}
				entry& operator=(const entry& other) {
					if(this != &other) {
						char* tmpname = (char*)calloc(strlen(other.name)+1, 1);
						if(!tmpname) throw std::bad_alloc();
						free(name);
						name = tmpname;
						type = other.type;
						strcpy(name, other.name);
					}
					return *this;
				}
				entry& operator=(entry&& other) {
					if(this != &other) {
						name = other.name;
						other.name = nullptr;
						type = other.type;
						other.type = -1;
					}
					return *this;
				}
				entry() : name(NULL), type(-1) {}
				entry(const entry& other) : entry() {*this = other;}
				entry(entry&& other) : entry() {*this = other;}
				~entry() {free(name);}
				friend class DirFileList;
				friend int DirectoryListing(DirFileList& output, const char* path);
			};
		private:
			char* original_path;
			std::vector<entry*> entries;
			void Clear() {
				for(size_t i = 0; i < entries.size(); i++)
					delete entries[i];
				entries.clear();
				free(original_path);
				original_path = nullptr;
			}
		public:
			const entry& operator[](int index) const {
				return *(entries.at(index));
			}
			DirFileList& operator=(const DirFileList& other) {
				if(this != &other) {
					Clear();
					char* new_path = (char*)malloc(strlen(other.original_path)+1);
					if(!new_path) throw std::bad_alloc();
					strcpy(new_path, other.original_path);
					original_path = new_path;
					for(size_t i = 0; i < other.entries.size(); i++) {
						entry* foo = nullptr;
						try {
							foo = new entry(*other.entries[i]);
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
			DirFileList& operator=(DirFileList&& other) {
				if(this != &other) {
					free(original_path);
					original_path = other.original_path;
					other.original_path = nullptr;
					entries = std::move(other.entries);
				}
				return *this;
			}
			std::string operator+(const entry& _entry) {
				return std::string(std::string(original_path) + std::string(_entry.name));
			}
			size_t size() const {return entries.size();}
			const char* GetPath() const {return original_path;};
			DirFileList() : original_path(nullptr) {}
			DirFileList(const char* path) : DirFileList() {DirectoryListing(*this, path);}
			DirFileList(const std::string& path) : DirFileList() {DirectoryListing(*this, path.c_str());}
			DirFileList(const DirFileList& other) : DirFileList() {*this = other;}
			DirFileList(DirFileList&& other) : DirFileList() {*this = other;}
			~DirFileList() {Clear();}
			friend int DirectoryListing(DirFileList& output, const char* path);
		};

		int MakeDirectory(const char* path, bool recursive = true);
		int RemoveDirectory(const char* path, bool recursive = true);
		int DirectoryListing(DirFileList& output, const char* path);
		int CheckIfDir(const char* path);
		int FixUpPath(char*& out, const char* path, bool ending_delimitor = true);
	}
}

#endif
