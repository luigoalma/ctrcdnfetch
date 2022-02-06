#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <memory>
#include <exception>
#include <stdexcept>
#include <new>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include "DownloadManager.hpp"
#include "DirectoryManagement.hpp"
#include "StorageControl.hpp"
#include "CDN.hpp"
#include "Ticket.hpp"
#include "Endian.hpp"
#include "types.h"

static void loadcerts(u8*& ptr, const char* proxy) {
	static const u8 expecteddigest[SHA256_DIGEST_LENGTH] = {0xDC, 0x15, 0x3C, 0x2B, 0x8A, 0x0A, 0xC8, 0x74, 0xA9, 0xDC, 0x78, 0x61, 0x0E, 0x6A, 0x8F, 0xE3, 0xE6, 0xB1, 0x34, 0xD5, 0x52, 0x88, 0x73, 0xC9, 0x61, 0xFB, 0xC7, 0x95, 0xCB, 0x47, 0xE6, 0x97};
	u8 digest[SHA256_DIGEST_LENGTH] = {};
	FILE* fp = NULL;
	u8* data = NULL;
	size_t read = 0;
	do {
		do {
			if(NintendoData::SharedStorage::Load(fp, "CA00000003-XS0000000c.bin")) break;
			data = (u8*)calloc(1792, 1);
			if(!data) break;
			if((read = fread(data, 1, 1792, fp)) == 1792)
				SHA256(data, 1792, digest);
		} while(0);
		if(fp) fclose(fp);
		if(data && read == 1792 && !memcmp(expecteddigest, digest, SHA256_DIGEST_LENGTH)) break;
		u8* ticket = NULL;
		try {
			if(!data) data = (u8*)calloc(1792, 1);
			if(!data) break;
			DownloadManager manager;
			manager.SetAttribute(DownloadManager::URL, "http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/0004013800000002/cetk")
				.SetAttribute(DownloadManager::BUFFER, true)
				.SetAttribute(DownloadManager::PROGRESS, false);
			if(proxy) manager.SetAttribute(DownloadManager::PROXY, proxy);
			auto downloader = manager.GetDownloader();
			if(!downloader.Download()) break;
			size_t tiklen = 0;
			ticket = (u8*)downloader.GetBufferAndDetach(tiklen);
			if(!ticket || !tiklen) {
				free(ticket);
				break;
			}
			NintendoData::Ticket tik(ticket, tiklen);
			if(tiklen - tik.TotalSize() != 1792) {
				free(ticket);
				break;
			}
			u8* certs = ticket + tik.TotalSize();
			SHA256(certs, 1792, digest);
			if(memcmp(expecteddigest, digest, SHA256_DIGEST_LENGTH)) {
				free(ticket);
				break;
			}
			NintendoData::SharedStorage::Save(certs, 1792, "CA00000003-XS0000000c.bin");
			memcpy(data, certs, 1792);
			read = 1792;
			free(ticket);
			break;
		} catch(...) {
			if(fp) fclose(fp);
			free(data);
			free(ticket);
			throw;
		}
		throw std::runtime_error("Couldn't load certs.");
	} while(0);
	ptr = data;
}

struct arguments {
	struct entry {
		const char* path = NULL;
		u16 version = 0;
		bool latest = true;
	};
	const char* proxy = NULL;
	std::vector<struct entry> files;
	bool printhelp = false;
	bool useforcetkregardless = false;
	bool printresponseheaders = false;
	bool nodownload = false;
};

static void print_usage(const char* ptr) {
	printf("Usage: %s [options] tickets [...]\n\n"
		"Options:\n"
		"  -p, --proxy [uri]         To set a proxy before connecting.\n"
		"      --use-for-cetk        Use tickets always for cetk\n"
		"                            Regardless they are eshop ones or not.\n"
		"                            This makes CIAs not installable but\n"
		"                            keeps original ticket on them.\n"
		"  -r, --response            Print response headers.\n"
		"  -n, --no-download         Doesn't download, implies -r.\n"
		"  -v, --version [num] [tik] Download specific version of a title.\n"
		"  -h, --help                Show this message.\n"
		"      --usage               Alias for help.\n"
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

static bool parse_a_title(std::string& strerr, struct arguments& args, int i, char** argv) {
	const char* reason;
	if((reason = checkifvalidticket(argv[i])) != NULL) {
		strerr += "Argument ignored: ";
		strerr += argv[i];
		strerr += "\n ";
		strerr += reason;
		strerr += "\n";
		return false;
	}
	bool found = false;
	for(size_t foo = 0; foo < args.files.size(); foo++) 
		if(!strcmp(argv[i], args.files[foo].path)) {
			found = true;
			break;
		}
	struct arguments::entry newentry;
	newentry.path = argv[i];
	if(!found) args.files.push_back(newentry);
	return !found;
}

//Clean? Nope. Works? yup.
//Enjoy indentation mess.
static void parse_args(struct arguments& args, int argc, char** argv) {
	try {
		std::string strerr;
		for(int i = 1; i < argc; i++) {
			if(!*argv[i]) continue; //?? shouldn't happen but I'll leave it in as a fail safe..
			if(*argv[i] != '-') {
				parse_a_title(strerr, args, i, argv);
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
					case 'r':
						args.printresponseheaders = true;
						break;
					case 'n':
						args.nodownload = true;
						args.printresponseheaders = true;
						break;
					case 'v':
						if(!argv[i + 1] || !argv[i + 2]) {
							strerr += "Argument ignored: v\n No more arguments.\n";
							continue;
						}
						if(!parse_a_title(strerr, args, i + 2, argv)) {
							i+=2;
							strerr += "Argument ignored: v\n Bad ticket path.\n";
							continue;
						}
						{
							auto version = strtoul(argv[i + 1], NULL, 0);
							if(version > 0xffff) {
								args.files.pop_back();
								strerr += "Argument ignored: v\n Bad Version.\n Won't process:\n ";
								strerr += argv[i + 2];
								strerr += "\n";
								i+=2;
								continue;
							}
							auto index = args.files.size()-1;
							args.files[index].version = version;
							args.files[index].latest = false;
						}
						i+=2;
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
			if(!strcmp(&argv[i][2], "use-for-cetk")) {
				args.useforcetkregardless = true;
				continue;
			}
			if(!strcmp(&argv[i][2], "response")) {
				args.printresponseheaders = true;
				continue;
			}
			if(!strcmp(&argv[i][2], "no-download")) {
				args.nodownload = true;
				args.printresponseheaders = true;
				continue;
			}
			if(!strcmp(&argv[i][2], "version")) {
				if(!argv[i + 1] || !argv[i + 2]) {
					strerr += "Argument ignored: v\n No more arguments.\n";
					continue;
				}
				if(!parse_a_title(strerr, args, i + 2, argv)) {
					i+=2;
					strerr += "Argument ignored: v\n Bad ticket path.\n";
					continue;
				}
				auto version = strtoul(argv[i + 1], NULL, 0);
				if(version > 0xffff) {
					args.files.pop_back();
					strerr += "Argument ignored: v\n Bad Version.\n Won't process:\n ";
					strerr += argv[i + 2];
					strerr += "\n";
					i+=2;
					continue;
				}
				auto index = args.files.size()-1;
				args.files[index].version = version;
				args.files[index].latest = false;
				i+=2;
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
	size_t mintikbufsize = NintendoData::Ticket::MinimumMaxSignSize();
	u8* mintikbuffer = (u8*)calloc(mintikbufsize, 1);
	u8* certs = NULL;
	try {
		loadcerts(certs, args.proxy);
	} catch(std::exception& e) {
		fprintf(stderr, "Something prevented the obtain ticket certificates.\n"
			"Can't continue.\n"
			"Caugth exception message: %s\n", e.what());
		return 1;
	}
	if(!mintikbuffer) {
		fprintf(stderr, "Something prevented the program to allocate memory to start.\n"
			"Can't continue.\n");
		return 1;
	}
	for(size_t i = 0; i < args.files.size(); i++) {
		//this only supports RSA_2048_SHA256 type and Root-CA00000003-XS0000000c issuer tickets.
		FILE *fp = fopen(args.files[i].path, "rb");
		if(!fp) {
			fprintf(stderr, "Failed to open \"%s\". Skipping...\n", args.files[i].path);
			continue;
		}
		auto readtotal = fread(mintikbuffer, 1, mintikbufsize, fp);
		if(readtotal < NintendoData::Ticket::MinimumMinSignSize()) {
			fprintf(stderr, "Failed to read minimum ticket bytes from \"%s\". Skipping...\n", args.files[i].path);
			fclose(fp);
			continue;
		}
		char *outpath = NULL;
		try {
			std::unique_ptr<u8[]> tikbuffer(nullptr);
			size_t tiksize;
			try {
				tiksize = NintendoData::Ticket::GetTotalSize(mintikbuffer, readtotal);
				if (tiksize > 1048510) { // cap 1MiB
					fprintf(stderr, "Ticket capped size hit. Skipping \"%s\"\n", args.files[i].path);
					fclose(fp);
					continue;
				}
				tikbuffer = std::unique_ptr<u8[]>(new u8[tiksize]);
			} catch(...) {
				fclose(fp);
				throw;
			}
			rewind(fp);
			readtotal = fread(tikbuffer.get(), 1, tiksize, fp);
			fclose(fp);
			if (readtotal != tiksize) {
				fprintf(stderr, "Ticket size is %lu, read %lu. Skipping \"%s\"\n", tiksize, readtotal, args.files[i].path);
				continue;
			}
			NintendoData::Ticket tik(tikbuffer.get(), readtotal, true);
			bool skip = false;
			for(size_t j = 0; j < processedtids.size(); j++) 
				if(processedtids[j] == tik.TitleID()) {
					skip = true;
					break;
				}
			if(skip) {
				printf("Skipping \"%s\", already downloaded title from ticket.\n", args.files[i].path);
				continue;
			}
			NintendoData::Ticket cetk = tik;
			if(!args.useforcetkregardless && (tik.eShopID() || tik.ConsoleID())) {
				cetk.StripPersonalization();
			}
			printf("Downloading Title ID %016llX...\n", (unsigned long long)tik.TitleID());
			NintendoData::CDN cdnaccess(tik);
			if(args.proxy) cdnaccess.SetProxy(args.proxy);
			cdnaccess.SetHeaderPrint(args.printresponseheaders);
			size_t len = 0;
			if(!args.nodownload) {
				len = snprintf(NULL, 0, "%016llX/cetk", (unsigned long long)cdnaccess.GetTitleId());
				outpath = (char*)calloc(len+1, 1);
				if(!outpath) throw std::bad_alloc();
				snprintf(outpath, len+1, "%016llX", (unsigned long long)cdnaccess.GetTitleId());
				if(Utils::DirectoryManagement::MakeDirectory(outpath))
					throw std::runtime_error("Failed to create directory");
			} else {
				cdnaccess.SetNoDownload(true);
				outpath = NULL;
			}
			if(!args.files[i].latest) cdnaccess.SetVersion(args.files[i].version);
			cdnaccess.Download(outpath);
			if(!args.nodownload) {
				snprintf(outpath, len+1, "%016llX/cetk", (unsigned long long)cdnaccess.GetTitleId());
				fp = fopen(outpath, "wb");
				if(!fp) {
					fprintf(stderr, "Failed to open \"%s\". Skipping...\n", outpath);
					free(outpath);
					continue;
				}
				fwrite(cetk.GetRaw(), 1, cetk.TotalSize(), fp);
				fwrite(certs, 1, 1792, fp);
				fclose(fp);
				free(outpath);
			}
			outpath = NULL;
			processedtids.push_back(cdnaccess.GetTitleId());
		} catch(std::exception& e) {
			fflush(stdout);
			fprintf(stderr, "Something prevented the program to download target.\n"
				"Skipping \"%s\"...\n"
				"Caugth exception message: %s\n\n", args.files[i].path, e.what());
			free(outpath);
			outpath = NULL;
			continue;
		}
	}
	return 0;
}