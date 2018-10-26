#ifndef __DOWNLOADMANAGER_HPP__
#define __DOWNLOADMANAGER_HPP__
#include <curl/curl.h>
#include <exception>
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
	bool bufferflag;
	bool printheaders;
	bool immediate;
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
		bool bufferflag;
		bool printheaders;
		static int xferinfo(void *p, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) noexcept;
		static int older_progress(void *p, double dltotal, double dlnow, double ultotal, double ulnow) noexcept;
		static size_t write_data(void *ptr, size_t size, size_t nmemb, void *data) noexcept;
		static size_t headerprint(void *ptr, size_t size, size_t nmemb, void *data) noexcept;
		explicit Downloader(DownloadManager& data);
	public:
		~Downloader() noexcept;
		u64 Download() noexcept;
		void* GetBufferAndDetach(size_t& length) noexcept {
			void* ptr = buffer_data.buffer;
			buffer_data.buffer = NULL;
			length = buffer_data.size;
			buffer_data.size = 0;
			return ptr;
		}
		bool WasLastAttemptSuccess() noexcept {
			return res == CURLE_OK;
		}
		friend class DownloadManager;
	};
	DownloadManager& SetAttribute(Strtype type, const char* str, ...) noexcept;
	DownloadManager& SetAttribute(Flagtype type, bool flag) noexcept;
	DownloadManager& SetAttribute(progress_func function) noexcept;
	DownloadManager& SetAttribute(void* extra) noexcept;
	Downloader GetDownloader() {
		return Downloader(*this);
	}
	DownloadManager();
	~DownloadManager() noexcept;
protected:
	static CURLcode InitLib() noexcept;
	struct curl_slist* SlistClone() noexcept;
	friend class Downloader;
};

#endif