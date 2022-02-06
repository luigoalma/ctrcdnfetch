#ifndef __TMD_HPP__
#define __TMD_HPP__
#include <stdexcept>
#include "Endian.hpp"
#include "types.h"

namespace NintendoData {
	class TMD {
	public:
		enum class SignatureType : u32 {
			RSA_4096_SHA1 = 0x10000,
			RSA_2048_SHA1,
			ECDSA_SHA1,
			RSA_4096_SHA256,
			RSA_2048_SHA256,
			ECDSA_SHA256
		};
		#pragma pack(push,1)
		struct Header {
			char Issuer[64];
			u8 Version;
			u8 CaCrlVersion;
			u8 SignerCrlVersion;
			u8 Reserved1;
			u64 SystemVersion;
			u64 TitleID;
			u32 TitleType;
			u16 GroupID;
			u32 SaveDataSize;
			u32 SRLPrivateSaveDataSize;
			u32 Reserved2;
			u8 SRLFlag;
			u8 Reserved3[0x31];
			u32 AccessRights;
			u16 TitleVersion;
			u16 ContentCount;
			u16 BootContent;
			u16 Padding;
			u8 SHA256ContentInfoDigest[0x20];
		};
		struct ContentInfoRecords {
			u16 IndexOffset;
			u16 CommandCount;
			u8 SHA256ContentRecords[0x20];
		};
		struct ContentChunkRecords {
			u32 ContentId;
			u16 ContentIndex;
			u16 ContentType;
			u64 ContentSize;
			u8 SHA256[0x20];
			u32 GetContentId() const {return Endian::Be(ContentId);}
			u16 GetContentIndex() const {return Endian::Be(ContentIndex);}
			u16 GetContentType() const {return Endian::Be(ContentType);}
			u64 GetContentSize() const {return Endian::Be(ContentSize);}
			bool IsOptional() const {return (GetContentType() & 0x4000) != 0;}
		};
		#pragma pack(pop)
	private:
		u8* rawtmd;
		struct Header *header;
		struct ContentInfoRecords *inforecords;
		struct ContentChunkRecords *chunkrecords;
	public:
		TMD& operator=(const TMD& other);
		TMD& operator=(TMD&& other);
		static size_t MaxTMDSize() {
			return 0x240u + sizeof(struct Header) + 64u * sizeof(struct ContentInfoRecords) + 0x10000u * sizeof(struct ContentChunkRecords);
		}
		u16 GetContentCount() const {
			return Endian::Be(header->ContentCount);
		}
		const struct ContentInfoRecords &InfoRecord(const int index) const {
			if(index < 0 || index > 64) std::out_of_range("TMDs only have 64 info records. Excepted range from 0 to 63.");
			return inforecords[index];
		}
		const struct ContentChunkRecords &ChunkRecord(const int index) const {
			if(index < 0 || index > GetContentCount()) std::out_of_range("TMD doesn't have that many content records.");
			return chunkrecords[index];
		}
		bool IsStubbed() const;
		size_t FullSize() const {
			return (uptr)chunkrecords - (uptr)rawtmd + sizeof(struct ContentChunkRecords) * Endian::Be(header->ContentCount);
		}
		TMD();
		TMD(const void* ptr, size_t ptrlen);
		TMD(const TMD& other) : rawtmd(NULL) {*this = other;}
		TMD(TMD&& other) : rawtmd(NULL) {*this = std::move(other);}
		~TMD();
	};
}

#endif