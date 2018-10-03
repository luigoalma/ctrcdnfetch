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
		u64 GetTitleId() const noexcept {return tik.TitleID();}
		void Download(const char* outdir);
	private:
		void Init() {
			manager.SetAttribute(DownloadManager::HEADER, "Accept:")
				.SetAttribute(DownloadManager::HEADER, "Connection: Keep-Alive");	
		}
	public:
		CDN(const Ticket& ticket) : tik(ticket, true) {Init();}
		CDN(const void* ticket, size_t ticketlen) : tik(ticket, ticketlen, true) {
			Init();
		}
		~CDN() noexcept {}
	};
}

#endif