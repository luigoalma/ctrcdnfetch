#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <exception>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include "DownloadManager.hpp"
#include "CDN.hpp"
#include "Ticket.hpp"
#include "types.h"

//#warning "Incomplete and in testing code."

#if (defined _WIN16 || defined _WIN32 || defined _WIN64) && !defined __CYGWIN__
#define goodmkdir(x,y) mkdir(x)
#else
#define goodmkdir(x,y) mkdir(x,y)
#endif

static void ensuredirectory(const char* path) {
	struct stat buffer;
	memset(&buffer, 0, sizeof(struct stat));
	if(stat(path, &buffer) == 0) {
		if((buffer.st_mode&S_IFMT) == S_IFDIR) return;
		else {
			std::string message("Failed to create directory because it exists but it's not a directory:\n ");
			message += path;
			throw std::runtime_error(message);
		} 
	}
	if(goodmkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
		std::string message("Failed to create directory: ");
		message += path;
		throw std::runtime_error(message);
	}
}

//common code
static bool trycertloading(u8* ptr, std::string& str, std::string& firstgooddir) {
	struct stat buffer;
	memset(&buffer, 0, sizeof(struct stat));
	if(stat(str.c_str(), &buffer) != 0) return false;
	if((buffer.st_mode&S_IFMT) != S_IFDIR) return false;
	if(firstgooddir.empty()) firstgooddir = str;
	str += "/CA00000003-XS0000000c.bin";
	if(stat(str.c_str(), &buffer) != 0) return false;
	if((buffer.st_mode&S_IFMT) != S_IFREG && buffer.st_size != 1792) return false;
	FILE* fp = fopen(str.c_str(), "rb");
	if(!fp) return false;
	auto read = fread(ptr, 1, 1792, fp);
	fclose(fp);
	if(read != 1792) return false;
	static const u8 expecteddigest[SHA256_DIGEST_LENGTH] = {0xDC, 0x15, 0x3C, 0x2B, 0x8A, 0x0A, 0xC8, 0x74, 0xA9, 0xDC, 0x78, 0x61, 0x0E, 0x6A, 0x8F, 0xE3, 0xE6, 0xB1, 0x34, 0xD5, 0x52, 0x88, 0x73, 0xC9, 0x61, 0xFB, 0xC7, 0x95, 0xCB, 0x47, 0xE6, 0x97};
	u8 digest[SHA256_DIGEST_LENGTH];
	SHA256(ptr, 1792, digest);
	if(memcmp(expecteddigest, digest, SHA256_DIGEST_LENGTH)) return false;
	return true;
}

static void loadcerts(u8*& ptr, const char* proxy) {
	ptr = (u8*)calloc(1792, 1);
	if(!ptr) throw std::bad_alloc();
	std::string firstgooddir("");
	char* home = NULL;
	#if defined _WIN16 || defined _WIN32 || defined _WIN64
	do {
		std::string path("");
		char* appdata = getenv("APPDATA");
		if(!appdata) break;
		path += appdata;
		path += "/3ds";
		if(!trycertloading(ptr, path, firstgooddir)) break;
		return;
	} while(0);
	#endif
	#if defined _WIN16 || defined _WIN32 || defined _WIN64
	home = getenv("USERPROFILE");
	#else
	home = getenv("HOME");
	#endif
	#if defined __APPLE__ && defined __MACH__
	do {
		if(!home) break;
		std::string path("");
		path += home;
		path += "/Library/Application Support/3ds";
		if(!trycertloading(ptr, path, firstgooddir)) break;
		return;
	} while(0);
	#endif
	do {
		if(!home) break;
		std::string path("");
		path += home;
		path += "/.3ds";
		if(!trycertloading(ptr, path, firstgooddir)) break;
		return;
	} while(0);
	do {
		if(!home) break;
		std::string path("");
		path += home;
		path += "/3ds";
		if(!trycertloading(ptr, path, firstgooddir)) break;
		return;
	} while(0);
	do {
		if(firstgooddir.empty()) {
			if(!home) break;
			std::string path("");
			path += home;
			path += "/.3ds";
			ensuredirectory(path.c_str());
			firstgooddir = path;
		}
		DownloadManager manager;
		manager.SetAttribute(DownloadManager::URL, "http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/0004013800000002/cetk")
			.SetAttribute(DownloadManager::BUFFER, true)
			.SetAttribute(DownloadManager::PROGRESS, false);
		if(proxy) manager.SetAttribute(DownloadManager::PROXY, proxy);
		auto downloader = manager.GetDownloader();
		if(!downloader.Download()) break;
		size_t tiklen = 0;
		u8* ticket = (u8*)downloader.GetBufferAndDetach(tiklen);
		if(!ticket || !tiklen) {
			free(ticket);
			break;
		}
		try {
			NintendoData::Ticket tik(ticket, tiklen);
			if(tiklen - tik.TotalSize() != 1792) {
				free(ticket);
				break;
			}
			u8* certs = ticket + tik.TotalSize();
			static const u8 expecteddigest[SHA256_DIGEST_LENGTH] = {0xDC, 0x15, 0x3C, 0x2B, 0x8A, 0x0A, 0xC8, 0x74, 0xA9, 0xDC, 0x78, 0x61, 0x0E, 0x6A, 0x8F, 0xE3, 0xE6, 0xB1, 0x34, 0xD5, 0x52, 0x88, 0x73, 0xC9, 0x61, 0xFB, 0xC7, 0x95, 0xCB, 0x47, 0xE6, 0x97};
			u8 digest[SHA256_DIGEST_LENGTH];
			SHA256(certs, 1792, digest);
			if(memcmp(expecteddigest, digest, SHA256_DIGEST_LENGTH)) {
				free(ticket);
				break;
			}
			memcpy(ptr, certs, 1792);
			std::string path(firstgooddir);
			path += "/CA00000003-XS0000000c.bin";
			FILE* fp = fopen(path.c_str(), "wb");
			if(!fp) {
				free(ticket);
				return; //at this point, we won't error, but it would be good if we could save this..
			}
			fwrite(certs, 1, 1792, fp);
			fclose(fp);
			free(ticket);
			return;
		} catch(...) {
			free(ticket);
			throw;
		}
	} while(0);
	throw std::runtime_error("Couldn't load certs.");
}

struct arguments {
	const char* proxy = NULL;
	std::vector<const char*> files;
	bool printhelp = false;
};

//not that much.. yet 
static void print_usage(const char* ptr) {
	printf("Usage: %s [options] tickets [...]\n\n"
		"Options:\n"
		"  -p, --proxy [uri]   To set a proxy before connecting.\n"
		"  -h, --help          Show this message.\n"
		"      --usage         Alias for help.\n"
		"\nProxy format:\n"
		"  http[s]://[user[:password]@]example.org[:port]\n"
		"  socks4[a]://[user[:password]@]example.org[:port]\n"
		"  socks5[h]://[user[:password]@]example.org[:port]\n"
		"  ...other schemes and formats that used libcurl supports.\n", ptr);
}

//search for :// basically
//I'm putting trust on the user basically.....
static bool checkforurlscheme(const char* ptr) {
	for(; ptr[0] && ptr[1] && ptr[2]; ptr++) if(ptr[0] == ':' && ptr[1] == '/' && ptr[2] == '/') return true;
	return false;
}

static const char* checkifvalidticket(const char* ptr) {
	struct stat buffer;
	memset(&buffer, 0, sizeof(struct stat));
	if(stat(ptr, &buffer) != 0) return "Stat can't access target...";
	if((buffer.st_mode&S_IFMT) != S_IFREG) return "It's not a regular file.";
	if(buffer.st_size < 848) return "File is too small than we expected...";
	return NULL;
}

//Clean? Nope. Works? yup.
//Enjoy indentation mess.
static void parse_args(struct arguments& args, int argc, char** argv) {
	try {
		std::string strerr;
		for(int i = 1; i < argc; i++) {
			if(!*argv[i]) continue; //?? shouldn't happen but I'll leave it in as a fail safe..
			if(*argv[i] != '-') {
				const char* reason;
				if((reason = checkifvalidticket(argv[i])) != NULL) {
					strerr += "Argument ignored: ";
					strerr += argv[i];
					strerr += "\n ";
					strerr += reason;
					strerr += "\n";
					continue;
				}
				bool found = false;
				for(size_t foo = 0; foo < args.files.size(); foo++) 
					if(!strcmp(argv[i], args.files[foo])) {
						found = true;
						break;
					}
				if(!found) args.files.push_back(argv[i]);
				continue;
			}
			if(!argv[i][1]) {
				strerr += "Argument ignored: ";
				strerr += argv[i];
				strerr += "\n";
				continue;
			}
			if(argv[i][1] != '-') {
				int current = i;
				for(int j = 1; argv[current][j]; j++) {
					switch(argv[current][j]) {
					case 'h':
						args.printhelp = true;
						throw 0;
						break;
					case 'p':
						if(!argv[i + 1]) {
							strerr += "Argument ignored: p\n No proxy url argument found.\n";
							continue;
						}
						if(!checkforurlscheme(argv[i + 1])) {
							strerr += "Argument ignored: p\n No valid proxy url scheme found.\n";
							continue;
						}
						args.proxy = argv[++i];
						break;
					default:
						strerr += "Argument ignored: ";
						strerr += argv[current][j];
						strerr += "\n Doesn't exist.\n";
						break;
					}
				}
				continue;
			}
			//last but not least, -- arguments
			if(!argv[i][2]) {
				strerr += "Argument ignored: ";
				strerr += argv[i];
				strerr += "\n";
				continue;
			}
			if(!strcmp(&argv[i][2], "proxy")) {
				if(!argv[i + 1]) {
					strerr += "Argument ignored: p\n No proxy url argument found.\n";
					continue;
				}
				if(!checkforurlscheme(argv[i + 1])) {
					strerr += "Argument ignored: p\n No proxy url scheme found.\n";
					continue;
				}
				args.proxy = argv[++i];
				continue;
			}
			if(!strcmp(&argv[i][2], "help") || !strcmp(&argv[i][2], "usage")) {
				args.printhelp = true;
				throw 0;
				continue;
			}
			strerr += "Argument ignored: ";
			strerr += argv[i];
			strerr += "\n Doesn't exist.\n";
		}
		if(!strerr.empty()) fprintf(stderr, "%s\n", strerr.c_str());
	} catch (int) {}
}

int main(int argc, char** argv) {
	struct arguments args;
	try {
		parse_args(args, argc, argv);
	} catch(std::exception& e) {
		fprintf(stderr, "Something prevented the program to parse arguments.\n"
			"Can't continue.\n"
			"Caugth exception message: %s\n", e.what());
		return 1;
	}
	if(args.printhelp || argc < 2) {
		print_usage(argv[0]);
		return 0;
	}
	if(args.proxy) printf("[INFO] Using proxy: %s\n", args.proxy);
	std::vector<u64> processedtids;
	u8* tikbuffer = (u8*)calloc(848, 1);
	u8* certs = NULL;
	try {
		loadcerts(certs, args.proxy);
	} catch(std::exception& e) {
		fprintf(stderr, "Something prevented the obtain ticket certificates.\n"
			"Can't continue.\n"
			"Caugth exception message: %s\n", e.what());
		return 1;
	}
	if(!tikbuffer) {
		fprintf(stderr, "Something prevented the program to allocate memory to start.\n"
			"Can't continue.\n");
		return 1;
	}
	for(size_t i = 0; i < args.files.size(); i++) {
		//this only supports RSA_2048_SHA256 type and Root-CA00000003-XS0000000c issuer tickets.
		FILE *fp = fopen(args.files[i], "rb");
		if(!fp) {
			fprintf(stderr, "Failed to open \"%s\". Skipping...\n", args.files[i]);
			continue;
		}
		auto readtotal = fread(tikbuffer, 1, 848, fp);
		if(readtotal != 848) {
			fprintf(stderr, "Failed to read 848 bytes from \"%s\". Skipping...\n", args.files[i]);
			fclose(fp);
			continue;
		}
		fclose(fp);
		char *outpath = NULL;
		try {
			NintendoData::Ticket tik(tikbuffer, 848, true);
			bool skip = false;
			for(size_t j = 0; j < processedtids.size(); j++) 
				if(processedtids[j] == tik.TitleID()) {
					skip = true;
					break;
				}
			if(skip) {
				printf("Skipping \"%s\", already downloaded title from ticket.\n", args.files[i]);
				continue;
			}
			printf("Downloading Title ID %016llX...\n", (unsigned long long)tik.TitleID());
			NintendoData::CDN cdnaccess(tik);
			if(args.proxy) cdnaccess.SetProxy(args.proxy);
			size_t len = snprintf(NULL, 0, "%016llX/cetk", (unsigned long long)cdnaccess.GetTitleId());
			outpath = (char*)calloc(len+1, 1);
			if(!outpath) throw std::bad_alloc();
			snprintf(outpath, len+1, "%016llX", (unsigned long long)cdnaccess.GetTitleId());
			ensuredirectory(outpath);
			cdnaccess.Download(outpath);
			snprintf(outpath, len+1, "%016llX/cetk", (unsigned long long)cdnaccess.GetTitleId());
			fp = fopen(outpath, "wb");
			if(!fp) {
				fprintf(stderr, "Failed to open \"%s\". Skipping...\n", outpath);
				free(outpath);
				continue;
			}
			fwrite(tikbuffer, 1, 848, fp);
			fwrite(certs, 1, 1792, fp);
			fclose(fp);
			free(outpath);
			processedtids.push_back(cdnaccess.GetTitleId());
		} catch(std::exception& e) {
			fflush(stdout);
			fprintf(stderr, "Something prevented the program to download target.\n"
				"Skipping \"%s\"...\n"
				"Caugth exception message: %s\n\n", args.files[i], e.what());
			free(outpath);
			continue;
		}
	}
	return 0;
}