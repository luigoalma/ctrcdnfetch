#undef LIBCURL_VERSION_NUM //imma try to ensure there's no cheating builds with at commandline definitions.
#define _DEFAULT_SOURCE
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <new>
#include <mutex>
#include "DownloadManager.hpp"

#define UNUSED(i) (void)i

#if LIBCURL_VERSION_NUM < 0x073700
#error "Supporting at minimum version libcurl 7.55.0"
#endif

static std::recursive_mutex global_proxy_lock;
static const char* global_proxy = NULL;

int DownloadManager::Downloader::xferinfo(void *p, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
	UNUSED(ultotal); UNUSED(ulnow); //build warning suppression
	struct progress_data *progress = (struct progress_data*)p;
	if((dlnow - progress->last_print_value >= 20480 || dlnow == dltotal) && progress->last_print_value != dlnow ) {
		if(dltotal) printf("\rDownloading: %s... %5.01f%% %llu / %llu", progress->filename, (double)dlnow/(double)dltotal*100, (unsigned long long)dlnow, (unsigned long long)dltotal);
		if(dltotal && dltotal == dlnow) puts("");
		progress->last_print_value = dlnow;
		fflush(stdout);
	}
	return 0;
}

size_t DownloadManager::Downloader::write_data(void *ptr, size_t size, size_t nmemb, void *data) {
	Downloader* _this = (Downloader*)data;
	size_t realsize = size*nmemb;
	u64 totalsize = _this->downloaded + realsize;
	if(_this->limiteddownload && totalsize > _this->downloadlimit) return 0; // set limited reached
	_this->downloaded = totalsize;
	if(_this->bufferflag) {
		if(_this->buffer_data.size != totalsize){ //incase this function is called when realsize = 0
			u8* foo = (u8*)realloc(_this->buffer_data.buffer, totalsize);
			if(!foo) {
				free(_this->buffer_data.buffer);
				_this->buffer_data.buffer = NULL;
				return 0; //abort
			}
			_this->buffer_data.buffer = foo;
			memcpy((void*)(&((char*)_this->buffer_data.buffer)[_this->buffer_data.size]), ptr, realsize);
			_this->buffer_data.size = totalsize;
			if(!_this->out) return realsize; //if no file, return now, to continue with download to buffer
		}
	}
	if(_this->out) {
		return fwrite(ptr, size, nmemb, _this->out);
	}
	return 0; //this shouldn't happen?? but to suppress warnings and to be sure..
}

size_t DownloadManager::Downloader::headerprint(void *ptr, size_t size, size_t nmemb, void *data) {
	Downloader* _this = (Downloader*)data;
	size_t realsize = size*nmemb;
	size_t totalsize = _this->header_data.size + realsize;
	if(_this->header_data.size == totalsize) //incase this function is called when realsize = 0
		return 0;
	u8* foo = (u8*)realloc(_this->header_data.buffer, totalsize);
	if(!foo) {
		free(_this->header_data.buffer);
		_this->header_data.buffer = NULL;
		return 0; //abort
	}
	_this->header_data.buffer = foo;
	memcpy((void*)(&((char*)_this->header_data.buffer)[_this->header_data.size]), ptr, realsize);
	_this->header_data.size = totalsize;
	return realsize;
}

DownloadManager::Downloader::Downloader() :
  out(NULL),
  outpath(NULL),
  curl_handle(NULL),
  chunk(NULL),
  function(NULL),
  progress({}),
  buffer_data({}),
  header_data({}),
  res((CURLcode)~CURLE_OK),
  downloaded(0LLU),
  downloadlimit(0LLU),
  bufferflag(false),
  printheaders(false),
  limiteddownload(false)
{}

DownloadManager::Downloader::Downloader(DownloadManager& data) : Downloader() {
	data.lock();
	outpath = data.outpath;
	FILE* out = !outpath ? NULL : fopen(outpath, "wb");
	if(outpath && !out) {
		data.unlock();
		throw std::bad_alloc();
	}
	if(!out && !data.bufferflag && !data.printheaders) {
		data.unlock();
		throw std::runtime_error("No download location or buffer set.");
	}
	if(out) {
		fclose(out);
		out = NULL;
		remove(outpath); //remove empty file
	}
	if(data.chunk) chunk = data.SlistClone();
	curl_handle = curl_easy_duphandle(data.curl_handle);
	if((data.chunk && !chunk) || !curl_handle) {
		curl_easy_cleanup(curl_handle);
		curl_slist_free_all(chunk);
		data.unlock();
		throw std::bad_alloc();
	}
	function = !data.function ? &xferinfo : data.function;
	bufferflag = data.bufferflag;
	printheaders = data.printheaders;
	progress.filename = data.filename;
	progress.extradata = data.extraprogressdata;
	bool immediate = data.immediate;
	downloadlimit = data.downloadlimit;
	limiteddownload = data.limiteddownload;

	data.outpath = data.filename = NULL;
	data.extraprogressdata = NULL;
	data.bufferflag = data.immediate = false;
	data.unlock();

	curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, chunk);

	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, this);

	if(printheaders) {
		curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, headerprint);
		curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, this);
	}

	curl_easy_setopt(curl_handle, CURLOPT_XFERINFOFUNCTION, function);
	curl_easy_setopt(curl_handle, CURLOPT_XFERINFODATA, &this->progress);

	if(immediate) Download();
}

DownloadManager::Downloader::~Downloader() {
	free((void*)progress.filename);
	free(outpath);
	free(buffer_data.buffer);
	curl_easy_cleanup(curl_handle);
	curl_slist_free_all(chunk);
}

u64 DownloadManager::Downloader::Download() {
	downloaded = 0LLU;
	out = !outpath ? NULL : fopen(outpath, "wb");
	if(outpath && !out) {
		return 0;
	}
	if(!out && !bufferflag) {
		if(!printheaders) return 0;
		curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1L);
	}
	res = curl_easy_perform(curl_handle);
	if(out) fclose(out);
	if(res != CURLE_OK) {
		if(outpath) remove(outpath);
		free(buffer_data.buffer);
		free(header_data.buffer);
		buffer_data.buffer = NULL;
		buffer_data.size = 0;
		header_data.buffer = NULL;
		header_data.size = 0;
		return 0;
	}
	if(printheaders) {
		if(!header_data.buffer) {
			if(outpath) remove(outpath);
			free(buffer_data.buffer);
			buffer_data.buffer = NULL;
			buffer_data.size = 0;
			return 0;
		}
		fwrite(header_data.buffer, header_data.size, 1, stdout);
		fflush(stdout);
		free(header_data.buffer);
		header_data.buffer = NULL;
		header_data.size = 0;
	}
	curl_off_t dl = 0;
	curl_easy_getinfo(curl_handle, CURLINFO_SIZE_DOWNLOAD_T, &dl);
	if(!dl) { // 0 size??
		if(outpath) remove(outpath);
		free(buffer_data.buffer);
		buffer_data.buffer = NULL;
		buffer_data.size = 0;
		return 0;
	}
	return (u64)dl;
}

DownloadManager::Downloader& DownloadManager::Downloader::operator=(Downloader&& other) {
	if(this != &other) {
		this->~Downloader();
		out = other.out;
		other.out = NULL;
		outpath = other.outpath;
		other.outpath = NULL;
		curl_handle = other.curl_handle;
		other.curl_handle = NULL;
		chunk = other.chunk;
		other.chunk = NULL;
		function = other.function;
		other.function = NULL;
		progress.filename = other.progress.filename;
		progress.last_print_value = other.progress.last_print_value;
		progress.extradata = other.progress.extradata;
		other.progress = {NULL, 0, NULL};
		buffer_data.buffer = other.buffer_data.buffer;
		buffer_data.size = other.buffer_data.size;
		other.buffer_data = {NULL, 0};
		header_data.buffer = other.header_data.buffer;
		header_data.size = other.header_data.size;
		other.header_data = {NULL, 0};
		res = other.res;
		other.res = (CURLcode)~CURLE_OK;
		downloaded = other.downloaded;
		downloadlimit = other.downloadlimit;
		other.downloaded = other.downloadlimit = 0LLU;
		bufferflag = other.bufferflag;
		printheaders = other.printheaders;
		limiteddownload = other.limiteddownload;
		other.bufferflag = other.printheaders = other.limiteddownload = false;

		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, this);

		if(printheaders) {
			curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, headerprint);
			curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, this);
		}

		curl_easy_setopt(curl_handle, CURLOPT_XFERINFOFUNCTION, function);
		curl_easy_setopt(curl_handle, CURLOPT_XFERINFODATA, &this->progress);
	}
	return *this;
}

DownloadManager& DownloadManager::SetAttribute(DownloadManager::Strtype type, const char* str, ...) {
	lock();
	if(!str) str = "";
	va_list vaorig, vacopy;
	va_start(vaorig, str);
	do {
		va_copy(vacopy, vaorig);
		int len = vsnprintf(NULL, 0, str, vacopy) + 1;
		va_end(vacopy);
		if(len <= 1) break;
		char* newdata = (char*)calloc(len,1);
		if(!newdata) break;
		va_copy(vacopy, vaorig);
		vsnprintf(newdata, len, str, vacopy);
		va_end(vacopy);
		switch(type) {
		case FILENAME:
			free(filename);
			filename = newdata;
			break;
		case OUTPATH:
			free(outpath);
			outpath = newdata;
			break;
		case HEADER: { //cases don't create scopes, and I create a var in here, so... scope it is
				auto newchunk = curl_slist_append(chunk, newdata);
				if(newchunk) chunk = newchunk;
			}
			free(newdata);
			break;
		case URL:
			curl_easy_setopt(curl_handle, CURLOPT_URL, newdata);
			free(newdata);
			break;
		case PROXY:
			curl_easy_setopt(curl_handle, CURLOPT_PROXY, newdata);
			free(newdata);
			break;
		case PROXYUSERPWD:
			curl_easy_setopt(curl_handle, CURLOPT_PROXYUSERPWD, newdata);
			free(newdata);
			break;
		default: //what?
			free(newdata);
			break;
		}
	} while(0);
	va_end(vaorig);
	unlock();
	return *this;
}

DownloadManager& DownloadManager::SetAttribute(DownloadManager::Flagtype type, bool flag) {
	lock();
	switch(type) {
	case BUFFER:
		bufferflag = flag;
		break;
	case PROGRESS:
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, flag ? 0L : 1L);
		break;
	case IMMEDIATE:
		immediate = flag;
		break;
	case PRINTHEADER:
		printheaders = flag;
		break;
	}
	unlock();
	return *this;
}

DownloadManager& DownloadManager::SetAttribute(DownloadManager::progress_func function) {
	lock();
	this->function = function;
	unlock();
	return *this;
}

DownloadManager& DownloadManager::SetAttribute(void* extra) {
	lock();
	this->extraprogressdata = extra;
	unlock();
	return *this;
}

DownloadManager& DownloadManager::SetDownloadLimit(u64 limit) {
	lock();
	this->downloadlimit = limit;
	this->limiteddownload = true;
	unlock();
	return *this;
}

DownloadManager& DownloadManager::RemoveDownloadLimit() {
	lock();
	this->limiteddownload = false;
	unlock();
	return *this;
}

DownloadManager& DownloadManager::UseGlobalProxy() {
	global_proxy_lock.lock();
	if(!global_proxy) {
		global_proxy_lock.unlock();
		return *this;
	}
	this->SetAttribute(DownloadManager::PROXY, global_proxy);
	global_proxy_lock.unlock();
	return *this;
}

DownloadManager::DownloadManager() : filename(NULL), outpath(NULL), chunk(NULL), function(NULL), extraprogressdata(NULL), bufferflag(false), printheaders(false), immediate(false), limiteddownload(false) {
	if(InitLib() != CURLE_OK) throw std::runtime_error("Couldn't init libcurl or an instance of it.");
	#ifndef CURL_STATICLIB
	static bool versionchecked = false;
	if(!versionchecked) {
		auto data = curl_version_info(CURLVERSION_NOW);
		if(data->version_num < 0x073700) {
			std::string message("Supporting at minimum version libcurl 7.55.0\nDynamic library version is ");
			message += data->version;
			throw std::runtime_error(message);
		}
		versionchecked = true;
	}
	#endif
	if((curl_handle = curl_easy_init()) == NULL) throw std::runtime_error("Couldn't init libcurl or an instance of it.");
	curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
	curl_easy_setopt(curl_handle, CURLOPT_URL, "https://example.com"); //to not be blank setting
}

DownloadManager::~DownloadManager() {
	free(filename);
	free(outpath);
	curl_easy_cleanup(curl_handle);
	curl_slist_free_all(chunk);
}

CURLcode DownloadManager::InitLib() {
	static std::recursive_mutex lock;
	lock.lock();
	static int init = 0;
	CURLcode ret = CURLE_OK;
	if(!init){
		CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
		if(!res) init = 1;
		ret = res;
	}
	lock.unlock();
	return ret;
}

//slightly changed copy of Curl_slist_duplicate from libcurl code, since libcurl doesn't provide me one on normal lib usage, as of this writing
//correct me if wrong
struct curl_slist* DownloadManager::SlistClone() {
	struct curl_slist *outlist = NULL;
	struct curl_slist *tmp;
	struct curl_slist *inlist = chunk;

	while(inlist) {
		tmp = curl_slist_append(outlist, inlist->data);
		if(!tmp) {
			curl_slist_free_all(outlist);
			return NULL;
		}
		outlist = tmp;
		inlist = inlist->next;
	}
	return outlist;
}

void DownloadManager::SetGlobalProxy(const char* proxy) {
	char* tmp = NULL;
	if(proxy) {
		tmp = strdup(proxy);
		if(!tmp) throw std::bad_alloc();
	}
	global_proxy_lock.lock();
	free((void*)global_proxy);
	global_proxy = tmp;
	global_proxy_lock.unlock();
}
