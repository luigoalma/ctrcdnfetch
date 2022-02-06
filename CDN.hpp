#ifndef __CDN_HPP__
#define __CDN_HPP__
#include <vector>
#include <utility>
#include <stdexcept>
#include <exception>
#include "DownloadManager.hpp"
#include "Ticket.hpp"
#include "TMD.hpp"
#include "Cert.hpp"
#include "types.h"

namespace NintendoData {
	class CDN {
	private:
		Ticket tik;
		TMD tmd;
		CertList certs;
		u64 TitleID;
		::DownloadManager manager;
		u16 version;
		bool respect_ownership_rights;
		bool set_version;
		bool nodownload;
	public:
		template<typename... Args> CDN& SetProxy(const char* str, Args... args) {
			manager.SetAttribute(DownloadManager::PROXY, str, args...);
			return *this;
		}
		CDN& UseGlobalProxy() {
			manager.UseGlobalProxy();
			return *this;
		}
		CDN& SetProgressFunction(::DownloadManager::progress_func func) {
			manager.SetAttribute(func);
			return *this;
		}
		CDN& SetExtraProgressPtr(void *extra) {
			manager.SetAttribute(extra);
			return *this;
		}
		CDN& SetHeaderPrint(bool printheaders) {
			manager.SetAttribute(DownloadManager::PRINTHEADER, printheaders);
			return *this;
		}
		CDN& SetNoDownload(bool nodownload) {
			this->nodownload = nodownload;
			if(nodownload) SetHeaderPrint(true);
			return *this;
		}
		CDN& SetVersion(u16 version, bool set = true) {
			this->version = version;
			this->set_version = set;
			return *this;
		}
		CDN& RespectOwnership(bool set = true) {
			this->respect_ownership_rights = set;
			return *this;
		}
		u64 GetTitleId() const {return TitleID;}
		const Ticket& GetTicket() const {return tik;}
		const TMD& GetDownloadedTMD() const {return tmd;}
		const CertList& GetCertList() const {return certs;}
		bool IsSystemTitle() {
			u32 high_id = (u32)(TitleID >> 32);
			if((!(high_id & 0x8000) && high_id & 0x0010) || (high_id & 0x8001) == 0x8001) return true;
			return false;
		}
		bool IsDLCTitle() {
			u32 high_id = (u32)(TitleID >> 32);
			if(!(high_id & 0x8000) && (high_id & 0x008C) == 0x008C) return true;
			return false;
		}
		void Download(const char* outdir);
	private:
		void Init() {
			respect_ownership_rights = true;
			set_version = false;
			nodownload = false;
			manager.SetAttribute(DownloadManager::HEADER, "Accept:")
				.SetAttribute(DownloadManager::HEADER, "Connection: Keep-Alive");
		}
	public:
		CDN(u64 id) : TitleID(id) {
			if(!IsSystemTitle())
				throw std::runtime_error("CDN is restrictive, signed tickets needed for non system titles.");
			Init();
		}
		CDN(const Ticket& ticket) : tik(ticket, true), TitleID(tik.TitleID()) {Init();}
		CDN(const void* ticket, size_t ticketlen) : tik(ticket, ticketlen, true), TitleID(tik.TitleID()) {Init();}
		~CDN() {}
	};
}

#endif