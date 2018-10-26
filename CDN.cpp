#include "CDN.hpp"
#include "TMD.hpp"

void NintendoData::CDN::Download(const char* outdir) {
	static const char* baseurl = "http://ccs.cdn.c.shop.nintendowifi.net/ccs/download";
	char* b64_encticket = NULL;
	char* b64_encticketkey = NULL;
	u8 *tmdbuffer = NULL;
	size_t tmdlen = 0;
	tik.GetWrappedTicket(b64_encticket, b64_encticketkey);
	manager.SetAttribute(DownloadManager::HEADER, "X-Authentication-Key: %s", b64_encticketkey)
		.SetAttribute(DownloadManager::HEADER, "X-Authentication-Data: %s", b64_encticket);
	try {
		manager.SetAttribute(DownloadManager::FILENAME, "tmd")
			.SetAttribute(DownloadManager::URL, "%s/%016llX/tmd", baseurl, GetTitleId())
			.SetAttribute(DownloadManager::BUFFER, true)
			.SetAttribute(DownloadManager::PROGRESS, true);
		if(!nodownload) manager.SetAttribute(DownloadManager::OUTPATH, "%s/tmd", outdir);
		auto tmddownloader = manager.GetDownloader();
		if(!tmddownloader.Download()) throw std::runtime_error("Failed to download TMD");
		tmdbuffer = (u8*)tmddownloader.GetBufferAndDetach(tmdlen);
		if(!tmdbuffer || !tmdlen) throw std::runtime_error("Failed to download TMD to a buffer");
		TMD tmd(tmdbuffer, tmdlen);
		u16 tmdcontentcount = tmd.GetContentCount();
		for(u16 i = 0; i < tmdcontentcount; i++) {
			u32 id = tmd.ChunkRecord(i).GetContentId();
			if(nodownload) printf("%08x\n", id);
			manager.SetAttribute(DownloadManager::FILENAME, "%08x", id)
				.SetAttribute(DownloadManager::URL, "%s/%016llX/%08X", baseurl, GetTitleId(), id);
			if(!nodownload) manager.SetAttribute(DownloadManager::OUTPATH, "%s/%08x", outdir, id);
			auto downloader = manager.GetDownloader();
			if(downloader.Download() != tmd.ChunkRecord(i).GetContentSize() && !nodownload)
				throw std::runtime_error("Failed to download content or content size is invalid.");
		}
	} catch (...) {
		free(b64_encticket);
		free(b64_encticketkey);
		free(tmdbuffer);
		throw;
	}
	free(b64_encticket);
	free(b64_encticketkey);
	free(tmdbuffer);
}