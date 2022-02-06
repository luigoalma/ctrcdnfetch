#ifndef __TICKET_HPP__
#define __TICKET_HPP__
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <stdexcept>
#include <new>
#include "Endian.hpp"
#include "types.h"

namespace NintendoData {
	class Ticket {
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
			u8 ECC_PubKey[0x3C];
			u8 Version;
			u8 CaCrlVersion;
			u8 SignerCrlVersion;
			u8 TitleKey[16];
			u8 Reserved1;
			u64 TicketID;
			u32 ConsoleID;
			u64 TitleID;
			u16 Reserved2;
			u16 TicketTitleVersion;
			u64 Reserved3;
			u8 LicenseType;
			u8 KeyYIndex;
			u8 Reserved4[0x2A];
			u32 eShopID;
			u8 Reserved5;
			u8 Audit;
			u8 Reserved6[0x42];
			u8 Limits[0x40];
			u8 ContentIndex[];
			u64 GetTicketID() const {return Endian::Be(TicketID);}
			u32 GetConsoleID() const {return Endian::Be(ConsoleID);}
			u64 GetTitleID() const {return Endian::Be(TitleID);}
			u16 GetTicketTitleVersion() const {return Endian::Be(TicketTitleVersion);}
			u32 GeteShopID() const {return Endian::Be(eShopID);}
			u32 ContentIndexSize() const {return Endian::Be((u32*)&ContentIndex[4]);}
			u32 HeaderFullSize() const {return sizeof(Header) + ContentIndexSize();}
		};
		struct TicketRightsField {
		    u8 Unk[2];
		    u16 IndexOffset;
		    u8 RightsBitfield[0x80];
		};
		#pragma pack(pop)
	private:
		u8* rawticket;
		struct Header* header;
		u32 rightfieldcount;
		const struct TicketRightsField* rights;
	public:
		Ticket& operator=(const Ticket& other);
		Ticket& operator=(Ticket&& other);
		void GetWrappedTicket(char*& out_b64_encticket, char*& out_b64_encticketkey) const;
		const struct Header &GetHeader() const {return *header;}
		u64 TicketID() const {return GetHeader().GetTicketID();}
		u32 ConsoleID() const {return GetHeader().GetConsoleID();}
		u64 TitleID() const {return GetHeader().GetTitleID();}
		u16 GetTicketTitleVersion() const {return GetHeader().GetTicketTitleVersion();}
		u32 eShopID() const {return GetHeader().GeteShopID();}
		bool VerifySign() const;
		size_t TotalSize() const {return ((uptr)header - (uptr)rawticket) + header->HeaderFullSize();}
		bool RightsToContentIndex(int index) const;
		void StripPersonalization();
		static size_t MostCommonTicketSize() {return 0x350u;};
		static size_t MinimumNoSignSize() {return sizeof(Header) + 20;};
		static size_t MinimumMaxSignSize() {return 0x240 + MinimumNoSignSize();};
		static size_t MinimumMinSignSize() {return 0x80 + MinimumNoSignSize();};
		static size_t GetSignSize(const void* ptr, size_t ptrlen);
		static size_t GetTotalSize(const void* ptr, size_t ptrlen);
		const void* GetRaw() const {return rawticket;}
		Ticket();
		Ticket(const Ticket& other, bool mustbesigned = false) : Ticket() {
			if(mustbesigned && !other.VerifySign())
				throw std::invalid_argument("Ticket is not properly signed.");
			*this = other;
		}
		Ticket(Ticket&& other) : Ticket() {*this = other;}
		Ticket(const void* ptr, size_t ptrlen, bool mustbesigned = false);
		~Ticket();
	};
}
#endif