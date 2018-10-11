#define _DEFAULT_SOURCE
#define _FILE_OFFSET_BITS 64
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include "DirectoryManagement.hpp"

#if (defined _WIN16 || defined _WIN32 || defined _WIN64) && !defined __CYGWIN__
#define goodmkdir(x,y) mkdir(x)
#define DELIMITORS "/\\"
#else
#define goodmkdir(x,y) mkdir(x,y)
#define DELIMITORS "/"
#endif

int Utils::DirectoryManagement::CreateDirectory(const char* path, bool recursive) {
	if(!path) {
		errno = EFAULT;
		return errno;
	}
	struct stat buffer;
	memset(&buffer, 0, sizeof(struct stat));
	errno = 0;
	if(stat(path, &buffer) == 0) {
		if((buffer.st_mode&S_IFMT) != S_IFDIR) errno = ENOTDIR;
	} else if(recursive) {
		char* copypath = (char*)calloc(strlen(path)+1, 1);
		if(!copypath) {
			errno = ENOMEM;
			return errno;
		}
		strcpy(copypath, path);
		char* workstr = copypath;
		std::string progressivepath("");
		do {
			#if (defined _WIN16 || defined _WIN32 || defined _WIN64) && !defined __CYGWIN__
			//if [A to Z]: path start 
			if((path[0]&0xDF) >= 'A' && (path[0]&0xDF) <= 'Z' && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
				progressivepath += path[0];
				progressivepath += ":/";
				if(stat(progressivepath.c_str(), &buffer) != 0) return errno;
				workstr = copypath + 2;
				break;
			}
			if(path[0] == '\\') {
				progressivepath += '/';
				break;
			}
			#endif
			if(path[0] == '/')
				progressivepath += '/';
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
			progressivepath += '/';
		}
		free(copypath);
	} else if(errno == ENOENT) {
		#if (defined _WIN16 || defined _WIN32 || defined _WIN64) && !defined __CYGWIN__
		//if [A to Z]: path start 
		if((path[0]&0xDF) >= 'A' && (path[0]&0xDF) <= 'Z' && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
			std::string checkpath("");
			checkpath += path[0];
			checkpath += ":/";
			if(stat(checkpath.c_str(), &buffer) != 0) return errno;
		}
		#endif
		if(goodmkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == 0) errno = 0;
	}
	return errno;
}

int Utils::DirectoryManagement::DirectoryListing(DirFileList& output, const char* path) noexcept {
	if(!path) {
		errno = EFAULT;
		return errno;
	}
	DIR *dp;
	struct dirent *ep;
	struct stat buffer;
	memset(&buffer, 0, sizeof(struct stat));
	errno = 0;
	if(stat(path, &buffer) != 0) return errno;
	if((buffer.st_mode&S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		return errno;
	}
	if((dp = opendir(path)) == NULL) return errno;
	output.Clear();
	errno = 0; //ensure
	while ((ep = readdir(dp))) {
		DirFileList::entry* stuff = new(std::nothrow) DirFileList::entry();
		if(!stuff) {
			errno = ENOMEM;
			break;
		}
		size_t length = strnlen(ep->d_name, sizeof(ep->d_name)) + 1;
		stuff->name = (char*)calloc(length, 1);
		if(!stuff->name) {
			delete stuff;
			errno = ENOMEM;
			break;
		}
		stuff->type = (ep->d_type == DT_DIR ? 0 : (ep->d_type == DT_REG ? 1 : 2));
		try {
			output.entries.push_back(stuff);
		} catch (...) {
			delete stuff;
			errno = ENOMEM;
			break;
		}
	}
	if(errno) output.Clear();
	return errno;
}

int Utils::DirectoryManagement::CheckIfDir(const char* path) noexcept {
	if(!path) {
		errno = EFAULT;
		return errno;
	}
	struct stat buffer;
	memset(&buffer, 0, sizeof(struct stat));
	errno = 0;
	if(stat(path, &buffer) != 0) return errno;
	if((buffer.st_mode&S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
	}
	return errno;
}

#undef goodmkdir
#undef DELIMITORS
