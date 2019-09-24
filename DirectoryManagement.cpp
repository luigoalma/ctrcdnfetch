#define _DEFAULT_SOURCE
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include "DirectoryManagement.hpp"

#if defined _WIN16 || defined _WIN32 || defined _WIN64
#ifndef __CYGWIN__
#define goodmkdir(x,y) mkdir(x)
#define lstat(x,y) stat(x,y)
#endif
#define DELIMITORS "/\\"
#define DEFAULT_DELIMITOR '\\'
#else
#define goodmkdir(x,y) mkdir(x,y)
#define DELIMITORS "/"
#define DEFAULT_DELIMITOR '/'
#endif

int Utils::DirectoryManagement::MakeDirectory(const char* path, bool recursive) {
	if(!path) {
		errno = EFAULT;
		return errno;
	}
	struct stat buffer;
	memset(&buffer, 0, sizeof(struct stat));
	errno = 0;
	if(stat(path, &buffer) == 0) {
		if((buffer.st_mode&S_IFMT) != S_IFDIR) errno = ENOTDIR;
		if(!errno) return 0;
	}
	if(recursive) {
		char* copypath = (char*)calloc(strlen(path)+1, 1);
		if(!copypath) {
			errno = ENOMEM;
			return errno;
		}
		strcpy(copypath, path);
		char* workstr = copypath;
		std::string progressivepath("");
		do {
			#if defined _WIN16 || defined _WIN32 || defined _WIN64
			//if [A to Z]: path start 
			if((path[0]&0xDF) >= 'A' && (path[0]&0xDF) <= 'Z' && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
				progressivepath += path[0];
				progressivepath += ":\\";
				if(stat(progressivepath.c_str(), &buffer) != 0) return errno;
				workstr = copypath + 2;
				break;
			}
			if(path[0] == '\\') {
				progressivepath += DEFAULT_DELIMITOR;
				break;
			}
			#endif
			if(path[0] == '/')
				progressivepath += DEFAULT_DELIMITOR;
		} while(0);
		char* save = NULL, *str = workstr;
		for(;; str = NULL) {
			char* part = strtok_r(str, DELIMITORS, &save);
			if(!part) break; //we finished.
			progressivepath += part;
			if(stat(progressivepath.c_str(), &buffer) != 0) {
				if(errno != ENOENT) break;
				if(goodmkdir(progressivepath.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) break;
				errno = 0; //success? clear
			} else {
				if((buffer.st_mode&S_IFMT) != S_IFDIR) {
					errno = ENOTDIR;
					break;
				}
			}
			progressivepath += DEFAULT_DELIMITOR;
		}
		free(copypath);
	} else if(errno == ENOENT) {
		#if defined _WIN16 || defined _WIN32 || defined _WIN64
		//if [A to Z]: path start 
		if((path[0]&0xDF) >= 'A' && (path[0]&0xDF) <= 'Z' && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
			std::string checkpath("");
			checkpath += path[0];
			checkpath += ":\\";
			if(stat(checkpath.c_str(), &buffer) != 0) return errno;
		}
		#endif
		if(goodmkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == 0) errno = 0;
	}
	return errno;
}


int Utils::DirectoryManagement::RemoveDirectory(const char* path, bool recursive) {
	if(!path) {
		errno = EFAULT;
		return errno;
	}
	int ret = 0;
	char* fixedpath = NULL;
	char* tmp = NULL;
	if((ret = FixUpPath(fixedpath, path, false)) != 0) return errno;
	struct stat buffer;
	if(lstat(fixedpath, &buffer) != 0) return errno;
	if((buffer.st_mode&S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		return errno;
	}
	if(!recursive) { //just try delete given path, as is
		errno = 0;
		rmdir(fixedpath);
		ret = errno;
		free(fixedpath);
		errno = ret;
		return ret;
	}
	//my attempt at not doing recursive calling
	class helper {
	public:
		DirFileList path;
		size_t index;
		helper(const char* _path) : path(_path), index(0) {}
		helper(const std::string& _path) : path(_path), index(0) {}
		helper(helper&& other) {
			path = std::move(other.path);
			index = other.index;
			other.index = 0;
		}
	};
	try {
		std::vector<helper> v;
		v.push_back(helper(fixedpath));
		free(fixedpath);
		fixedpath = nullptr;
		while(!v.empty()) {
			while(v.back().index < v.back().path.size()) {
				if(v.back().path[v.back().index].GetType() == 0) { //folder
					auto tmp = v.back().index++;
					v.push_back(helper(v.back().path + v.back().path[tmp]));
					continue;
				}
				else unlink((v.back().path + v.back().path[v.back().index]).c_str()); //file or other
				v.back().index++;
			}
			if(rmdir(v.back().path.GetPath())) ret = errno;
			v.pop_back();
		}
	} catch (std::length_error &e) {
		ret = ENOMEM;
	} catch (std::bad_alloc &e) {
		ret = ENOMEM;
	} catch (...) {
		ret = ECANCELED;
	}
	free(fixedpath); //only needed if got an exception before the free above on the try block
	errno = ret;
	return ret;
}

int Utils::DirectoryManagement::DirectoryListing(DirFileList& output, const char* path) {
	if(!path) {
		errno = EFAULT;
		return errno;
	}
	DIR *dp;
	struct dirent *ep;
	struct stat buffer;
	memset(&buffer, 0, sizeof(struct stat));
	int ret = 0;
	if(stat(path, &buffer) != 0) return errno;
	if((buffer.st_mode&S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		return errno;
	}
	if((dp = opendir(path)) == NULL) return errno;
	output.Clear();
	while ((ep = readdir(dp))) {
		if(!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, "..")) continue;
		DirFileList::entry* stuff = new(std::nothrow) DirFileList::entry();
		if(!stuff) {
			ret = ENOMEM;
			break;
		}
		size_t length = strlen(ep->d_name) + 1;
		stuff->name = (char*)calloc(length, 1);
		if(!stuff->name) {
			delete stuff;
			ret = ENOMEM;
			break;
		}
		strcpy(stuff->name, ep->d_name);
		try {
			std::string pathcheck(path);
			#if defined _WIN16 || defined _WIN32 || defined _WIN64
			if(pathcheck.back() != '\\' || pathcheck.back() != '/')
			#else
			if(pathcheck.back() != '/')
			#endif
				pathcheck += DEFAULT_DELIMITOR;
			pathcheck += stuff->name;
			if(lstat(pathcheck.c_str(), &buffer) != 0) break;
		} catch (...) {
			delete stuff;
			ret = ENOMEM;
			break;
		}
		stuff->type = ((buffer.st_mode&S_IFMT) == S_IFDIR ? 0 : ((buffer.st_mode&S_IFMT) == S_IFREG ? 1 : 2));
		try {
			output.entries.push_back(stuff);
		} catch (...) {
			delete stuff;
			ret = ENOMEM;
			break;
		}
	}
	if(!ret) {
		char* copy_path = NULL;
		ret = FixUpPath(copy_path, path);
		if(!ret) output.original_path = copy_path;
	}
	if(ret) output.Clear();
	closedir(dp);
	errno = ret;
	return ret;
}

int Utils::DirectoryManagement::CheckIfDir(const char* path) {
	if(!path) {
		errno = EFAULT;
		return errno;
	}
	struct stat buffer;
	memset(&buffer, 0, sizeof(struct stat));
	errno = 0;
	if(stat(path, &buffer) != 0) return errno;
	if((buffer.st_mode&S_IFMT) != S_IFDIR)
		errno = ENOTDIR;
	return errno;
}

int Utils::DirectoryManagement::FixUpPath(char*& out, const char* path, bool ending_delimitor) {
	if(!path) {
		errno = EFAULT;
		return errno;
	}
	std::string fixedpath("");
	#if defined _WIN16 || defined _WIN32 || defined _WIN64
	if(path[0] == '/') fixedpath += DEFAULT_DELIMITOR;
	#else
	if(path[0] == '/' || path[0] == '\\') fixedpath += DEFAULT_DELIMITOR;
	#endif
	char* copypath = (char*)malloc(strlen(path)+1);
	if(!copypath) {
		errno = ENOMEM;
		return errno;
	}
	strcpy(copypath, path);
	int ret = 0;
	char* tmp = NULL;
	try {
		char* save = NULL, *str = copypath;
		for(;; str = NULL) {
			char* part = strtok_r(str, DELIMITORS, &save);
			if(!part) break; //we finished.
			fixedpath += part;
			fixedpath += DEFAULT_DELIMITOR;
		}
		if(!ending_delimitor) fixedpath.pop_back();
		tmp = (char*)calloc(fixedpath.size()+1,1);
		if(!tmp) {
			free(copypath);
			errno = ENOMEM;
			return errno;
		}
		fixedpath.copy(tmp, fixedpath.size());
		out = tmp;
	} catch (std::length_error &e) {
		ret = ENOMEM;
		free(tmp);
	} catch (std::bad_alloc &e) {
		ret = ENOMEM;
		free(tmp);
	} catch (...) {
		ret = ECANCELED;
		free(tmp);
	}
	free(copypath);
	errno = ret;
	return ret;
}

#undef goodmkdir
#undef DELIMITORS
