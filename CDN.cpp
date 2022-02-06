#include <cstdio>
#include <stdexcept>
#include <exception>
#include "CDN.hpp"
#include "TMD.hpp"
#include "Cert.hpp"
#include "types.h"

void NintendoData::CDN::Download(const char* outdir) {
	static const char* baseurl = "http://ccs.cdn.c.shop.nintendowifi.net/ccs/download";
	char* b64_encticket = NULL;
	char* b64_encticketkey = NULL;
	u8 *tmdbuffer = NULL, *cetkbuffer = NULL;
	size_t tmdlen = 0, cetklen = 0;
	try {
		if(!IsSystemTitle() && tik.VerifySign()) {
			tik.GetWrappedTicket(b64_encticket, b64_encticketkey);
			manager.SetAttribute(DownloadManager::HEADER, "X-Authentication-Key: %s", b64_encticketkey)
				.SetAttribute(DownloadManager::HEADER, "X-Authentication-Data: %s", b64_encticket);
			free(b64_encticket);
			free(b64_encticketkey);
			b64_encticket = b64_encticketkey = NULL;
		} else if(!IsSystemTitle()) {
			throw std::runtime_error("CDN is restricted in access, signed tickets required for non system titles.");
		}
		manager.SetAttribute(DownloadManager::PROGRESS, true);
		if(IsSystemTitle()) {
			manager.SetAttribute(DownloadManager::BUFFER, true);
			manager.SetAttribute(DownloadManager::FILENAME, "cetk")
				.SetAttribute(DownloadManager::URL, "%s/%016llX/cetk", baseurl, GetTitleId());
			if(!nodownload) manager.SetAttribute(DownloadManager::OUTPATH, "%s/cetk", outdir);
			DownloadManager::Downloader cetkdownloader = manager.GetDownloader();
			if(!cetkdownloader.Download()) throw std::runtime_error("Failed to download CETK");
			cetkbuffer = (u8*)cetkdownloader.GetBufferAndDetach(cetklen);
			if(!cetkbuffer || !cetklen) throw std::runtime_error("Failed to download CETK to a buffer");
			this->tik = Ticket(cetkbuffer, cetklen, true);
			free(cetkbuffer);
			cetkbuffer = NULL;
		}
		manager.SetAttribute(DownloadManager::BUFFER, true);
		if(set_version) {
			manager.SetAttribute(DownloadManager::FILENAME, "tmd.%d", version)
				.SetAttribute(DownloadManager::URL, "%s/%016llX/tmd.%d", baseurl, GetTitleId(), version);
			if(!nodownload) manager.SetAttribute(DownloadManager::OUTPATH, "%s/tmd.%d", outdir, version);
		} else {
			manager.SetAttribute(DownloadManager::FILENAME, "tmd")
				.SetAttribute(DownloadManager::URL, "%s/%016llX/tmd", baseurl, GetTitleId());
			if(!nodownload) manager.SetAttribute(DownloadManager::OUTPATH, "%s/tmd", outdir);
		}
		manager.SetDownloadLimit(TMD::MaxTMDSize() + Cert::MaxCertSize() * 2);
		DownloadManager::Downloader tmddownloader = manager.GetDownloader();
		manager.RemoveDownloadLimit();
		if(!tmddownloader.Download()) throw std::runtime_error("Failed to download TMD");
		tmdbuffer = (u8*)tmddownloader.GetBufferAndDetach(tmdlen);
		if(!tmdbuffer || !tmdlen) throw std::runtime_error("Failed to download TMD to a buffer");
		this->tmd = TMD(tmdbuffer, tmdlen);
		free(tmdbuffer);
		tmdbuffer = NULL;
		u16 tmdcontentcount = tmd.GetContentCount();
		for(u16 i = 0; i < tmdcontentcount; i++) {
			auto& chunk = tmd.ChunkRecord(i);
			if(respect_ownership_rights && !IsSystemTitle() && IsDLCTitle()) {
				bool norights = !tik.RightsToContentIndex(chunk.GetContentIndex());
				if(norights && !chunk.IsOptional())
					throw std::runtime_error("Ticket expressed lack of rights to a non optional TMD index!");
				if(norights)
					continue;
			}
			u32 id = chunk.GetContentId();
			if(nodownload) printf("%08x\n", id);
			manager.SetAttribute(DownloadManager::FILENAME, "%08x", id)
				.SetAttribute(DownloadManager::URL, "%s/%016llX/%08X", baseurl, GetTitleId(), id);
			if(!nodownload) manager.SetAttribute(DownloadManager::OUTPATH, "%s/%08x", outdir, id);
			manager.SetDownloadLimit(chunk.GetContentSize());
			DownloadManager::Downloader downloader = manager.GetDownloader();
			manager.RemoveDownloadLimit();
			if(downloader.Download() != chunk.GetContentSize() && !nodownload)
				throw std::runtime_error("Failed to download content or content size is invalid.");
		}
	} catch (...) {
		//could failed anywhere, freed data earlier is set to NULL so there's no danger here
		free(b64_encticket);
		free(b64_encticketkey);
		free(tmdbuffer);
		free(cetkbuffer);
		throw;
	}
}