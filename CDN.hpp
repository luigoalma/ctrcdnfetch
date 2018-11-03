#ifndef __CDN_HPP__
#define __CDN_HPP__
#include "DownloadManager.hpp"
#include "Ticket.hpp"
#include "types.h"

namespace NintendoData {
	class CDN {
	private:
		Ticket tik;
		::DownloadManager manager;
		u16 version;
		bool set_version;
		bool nodownload;
	public:
		template<typename... Args> CDN& SetProxy(const char* str, Args... args) noexcept {
			manager.SetAttribute(DownloadManager::PROXY, str, args...);
			return *this;
		}
		CDN& SetProgressFunction(::DownloadManager::progress_func func) noexcept {
			manager.SetAttribute(func);
			return *this;
		}
		CDN& SetExtraProgressPtr(void *extra) noexcept {
			manager.SetAttribute(extra);
			return *this;
		}
		CDN& SetHeaderPrint(bool printheaders) noexcept {
			manager.SetAttribute(DownloadManager::PRINTHEADER, printheaders);
			return *this;
		}
		CDN& SetNoDownload(bool nodownload) noexcept {
			this->nodownload = nodownload;
			if(nodownload) SetHeaderPrint(true);
			return *this;
		}
		CDN& SetVersion(u16 version) noexcept {
			this->version = version;
			this->set_version = true;
			return *this;
		}
		u64 GetTitleId() const noexcept {return tik.TitleID();}
		void Download(const char* outdir);
	private:
		void Init() {
			manager.SetAttribute(DownloadManager::HEADER, "Accept:")
				.SetAttribute(DownloadManager::HEADER, "Connection: Keep-Alive");	
		}
	public:
		CDN(const Ticket& ticket) : tik(ticket, true), set_version(false), nodownload(false) {Init();}
		CDN(const void* ticket, size_t ticketlen) : tik(ticket, ticketlen, true), set_version(false), nodownload(false) {Init();}
		~CDN() noexcept {}
	};
}

#endif