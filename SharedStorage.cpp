#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include "SharedStorage.hpp"
#include "DirectoryManagement.hpp"

#if defined _WIN16 || defined _WIN32 || defined _WIN64
#define HOME "USERPROFILE"
#define DELIMITORS "/\\"
#else
#define HOME "HOME"
#define DELIMITORS "/"
#endif

namespace {
	struct storage {
		const char* const path;
		const char* const env;
		int getfullpath(char*& fullpath) const noexcept {
			const char* foo = getenv(env);
			if(!foo) {
				errno = EADDRNOTAVAIL;
				return errno;
			}
			size_t length = snprintf(NULL, 0, path, foo) + 1;
			fullpath = (char*)calloc(length, 1);
			if(!fullpath) {
				errno = ENOMEM;
				return errno;
			}
			snprintf(fullpath, length, path, foo);
			errno = 0;
			return errno;
		}
		int checkpath() const noexcept {
			char* fullpath = NULL;
			int err = 0;
			if((err = getfullpath(fullpath)) != 0) {
				errno = err;
				return errno;
			}
			err = Utils::DirectoryManagement::CheckIfDir(fullpath);
			free(fullpath);
			errno = err;
			return errno;
		}
		int createpath() const noexcept {
			char* fullpath = NULL;
			int err = 0;
			if((err = getfullpath(fullpath)) != 0) {
				errno = err;
				return errno;
			}
			err = Utils::DirectoryManagement::MakeDirectory(fullpath);
			free(fullpath);
			errno = err;
			return errno;
		}
	};

	static const struct storage storages[] = {
		#if defined _WIN16 || defined _WIN32 || defined _WIN64
		{"%s/3ds", "APPDATA"},
		#endif
		#if defined __APPLE__ && defined __MACH__
		{"%s/Library/Application Support/3ds", "HOME"},
		#endif
		{"%s/.3ds", HOME},
		{"%s/3ds", HOME}
	};
}

int NintendoData::SharedStorage::Load(FILE*& out, const char* file) noexcept {
	if(!file) {
		errno = EFAULT;
		return errno;
	}
	if(!file[0]) {
		errno = EINVAL;
		return errno;
	}
	out = NULL;
	bool foundastorage = false;
	int err = 0;
	int i = 0;
	int numofstorages = sizeof(storages) / sizeof(struct storage);
	for(;;) {
		for(; i < numofstorages; i++)
			if((err = storages[i].checkpath()) == 0) break;
		if(i >= numofstorages) break;
		foundastorage = true;
		char* fullstoragepath = NULL;
		if((err = storages[i].getfullpath(fullstoragepath)) != 0)
			continue;
		size_t length = snprintf(NULL, 0, "%s/%s", fullstoragepath, file) + 1;
		char* fullpath = (char*)calloc(length, 1);
		if(!fullpath) {
			free(fullstoragepath);
			err = ENOMEM;
			continue;
		}
		snprintf(fullpath, length, "%s/%s", fullstoragepath, file);
		free(fullstoragepath);
		out = fopen(fullpath, "rb");
		if(!out) {
			err = errno;
			i++;
		};
		free(fullpath);
		if(out) {
			err = 0;
			break;
		}
	}
	if(!foundastorage) {
		for(i = 0; i < numofstorages; i++)
			if(!storages[i].createpath()) break;
	}
	errno = err;
	return errno;
}

int NintendoData::SharedStorage::Save(const void* in, size_t inlen, const char* file) noexcept {
	if(!file || (!in && inlen)) {
		errno = EFAULT;
		return errno;
	}
	if(!file[0]) {
		errno = EINVAL;
		return errno;
	}
	int err = 0;
	int i;
	int numofstorages = sizeof(storages) / sizeof(struct storage);
	for(i = 0; i < numofstorages; i++)
		if((err = storages[i].checkpath()) == 0) break;
	//failed, no storages.
	if(i >= numofstorages) {
		for(i = 0; i < numofstorages; i++)
			if((err = storages[i].createpath()) == 0) break;
		//failed, again?
		if(i >= numofstorages) {
			errno = err;
			return err;
		}
	}
	err = 0;
	char* filepathcopy = (char*)calloc(strlen(file)+1,1);
	if(!filepathcopy) {
		errno = ENOMEM;
		return errno;
	}
	strcpy(filepathcopy, file);
	char *part1 = NULL, *part2 = NULL;
	char *str = filepathcopy, *save = NULL;
	char *dirpath = (char*)calloc(1,1);
	size_t currentsize = 1; //start at one because will refer to null.
	if(!dirpath) {
		free(filepathcopy);
		errno = ENOMEM;
		return errno;
	}
	for(;; str = NULL) {
		part1 = strtok_r(str, DELIMITORS, &save);
		if(!part1) break;
		if(part2) {
			currentsize += 1 + strlen(part2); // a / and the string
			char* tmp = (char*)realloc(dirpath, currentsize);
			if(!tmp) {
				free(dirpath);
				free(filepathcopy);
				errno = ENOMEM;
				return errno;
			}
			dirpath = tmp;
			strcat(dirpath, part2);
			strcat(dirpath, "/");
		}
		part2 = part1;
	}
	free(filepathcopy);
	char* storagepath = NULL;
	if((err = storages[i].getfullpath(storagepath)) != 0) {
		free(dirpath);
		errno = err;
		return errno;
	}
	size_t length = snprintf(NULL, 0, "%s/%s", storagepath, dirpath) + 1;
	char* fullpath = (char*)calloc(length, 1);
	if(!fullpath) {
		free(storagepath);
		free(dirpath);
		errno = ENOMEM;
		return errno;
	}
	snprintf(fullpath, length, "%s/%s", storagepath, dirpath);
	free(dirpath);
	err = Utils::DirectoryManagement::MakeDirectory(fullpath);
	free(fullpath);
	if(err) {
		free(storagepath);
		errno = err;
		return errno;
	}
	length = snprintf(NULL, 0, "%s/%s", storagepath, file) + 1;
	fullpath = (char*)calloc(length, 1);
	if(!fullpath) {
		free(storagepath);
		errno = ENOMEM;
		return errno;
	}
	snprintf(fullpath, length, "%s/%s", storagepath, file);
	free(storagepath);
	FILE* fp = fopen(fullpath, "wb");
	if(!fp) return errno;
	if(inlen) {
		fwrite(in, inlen, 1, fp);
		if(fflush(fp)) {
			err = errno;
			fclose(fp);
			remove(fullpath);
			free(fullpath);
			errno = err;
			return errno;
		}
	}
	fclose(fp);
	free(fullpath);
	errno = 0;
	return errno;
}