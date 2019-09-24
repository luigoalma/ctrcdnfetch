#ifndef __DOWNLOADMANAGER_HPP__
#define __DOWNLOADMANAGER_HPP__
#include <curl/curl.h>
#include <mutex>
#include "types.h"

class DownloadManager : protected std::recursive_mutex {
public:
	enum Strtype {
		FILENAME = 0, //set out filename for progress info
		OUTPATH, //set full path to file for download
		HEADER, //set an header
		URL, //set the url
		PROXY, //set a proxy
		PROXYUSERPWD //set the proxy user and password (if not added within proxy url)
	};
	enum Flagtype {
		BUFFER = 0,
		PROGRESS,
		IMMEDIATE, //start downloading once running GetDownloader
		PRINTHEADER
	};
	typedef int (*progress_func)(void *p, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);
protected:
	char* filename;
	char* outpath;
	struct curl_slist* chunk;
	CURL* curl_handle;
	progress_func function;
	void* extraprogressdata;
	u64 downloadlimit;
	bool bufferflag;
	bool printheaders;
	bool immediate;
	bool limiteddownload;
public:
	class Downloader {
	public:
		struct progress_data {
			const char* filename;
			curl_off_t last_print_value;
			void* extradata;
		};
	private:
		FILE* out;
		char* outpath;
		CURL* curl_handle;
		struct curl_slist* chunk;
		progress_func function;
		struct progress_data progress;
		struct {
			void* buffer;
			size_t size;
		} buffer_data;
		struct {
			void* buffer;
			size_t size;
		} header_data;
		CURLcode res;
		u64 downloaded;
		u64 downloadlimit;
		bool bufferflag;
		bool printheaders;
		bool limiteddownload;
		static int xferinfo(void *p, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);
		static size_t write_data(void *ptr, size_t size, size_t nmemb, void *data);
		static size_t headerprint(void *ptr, size_t size, size_t nmemb, void *data);
		Downloader& operator=(const Downloader& other) {return *this;}
	public:
		Downloader& operator=(Downloader&& other);
	private:
		explicit Downloader();
		explicit Downloader(DownloadManager& data);
		Downloader(const Downloader& other);
	public:
		Downloader(Downloader&& other) : Downloader() {*this = other;}
		~Downloader();

		u64 Download();
		void* GetBufferAndDetach(size_t& length) {
			void* ptr = buffer_data.buffer;
			buffer_data.buffer = NULL;
			length = buffer_data.size;
			buffer_data.size = 0;
			return ptr;
		}
		bool WasLastAttemptSuccess() {
			return res == CURLE_OK;
		}
		friend class DownloadManager;
	};
	DownloadManager& SetAttribute(Strtype type, const char* str, ...);
	DownloadManager& SetAttribute(Flagtype type, bool flag);
	DownloadManager& SetAttribute(progress_func function);
	DownloadManager& SetAttribute(void* extra);
	DownloadManager& SetDownloadLimit(u64 limit);
	DownloadManager& RemoveDownloadLimit();
	DownloadManager& UseGlobalProxy();
	Downloader GetDownloader() {
		return Downloader(*this);
	}
	DownloadManager();
	~DownloadManager();
protected:
	static CURLcode InitLib();
	struct curl_slist* SlistClone();
	friend class Downloader;
public:
	static void SetGlobalProxy(const char* proxy);
};

#endif