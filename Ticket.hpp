#ifndef __TICKET_HPP__
#define __TICKET_HPP__
#include <cstdlib>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <new>
#include "Endian.hpp"
#include "types.h"

namespace NintendoData {
	class Ticket {
	public:
		enum SignatureType : u32 {
			RSA_4096_SHA1 = 0x10000,
			RSA_2048_SHA1,
			ECDSA_SHA1,
			RSA_4096_SHA256,
			RSA_2048_SHA256,
			ECDSA_SHA256
		};
		struct __attribute__((__packed__)) Header {
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
			u8 ContentIndex[0xAC];
			u64 GetTicketID() const noexcept {return Endian::Be(TicketID);}
			u32 GetConsoleID() const noexcept {return Endian::Be(ConsoleID);}
			u64 GetTitleID() const noexcept {return Endian::Be(TitleID);}
			u16 GetTicketTitleVersion() const noexcept {return Endian::Be(TicketTitleVersion);}
			u32 GeteShopID() const noexcept {return Endian::Be(eShopID);}
		};
	private:
		u8* rawticket;
		struct Header* header;
	public:
		Ticket& operator=(const Ticket& other) {
			if(this != &other) {
				size_t ticketlen = ((uptr)other.header - (uptr)other.rawticket) + sizeof(struct Header);
				u8* tmp = (u8*)calloc(ticketlen, 1);
				if(!tmp) throw std::bad_alloc();
				free(this->rawticket);
				this->rawticket = tmp;
				memcpy(this->rawticket, other.rawticket, ticketlen);
				this->header = (struct Header*)&this->rawticket[(uptr)other.header - (uptr)other.rawticket];
			}
			return *this;
		}
		void GetWrappedTicket(char*& out_b64_encticket, char*& out_b64_encticketkey) const;
		const struct Header &GetHeader() const noexcept {return *header;}
		u64 TicketID() const noexcept {return GetHeader().GetTicketID();}
		u32 ConsoleID() const noexcept {return GetHeader().GetConsoleID();}
		u64 TitleID() const noexcept {return GetHeader().GetTitleID();}
		u16 GetTicketTitleVersion() const noexcept {return GetHeader().GetTicketTitleVersion();}
		u32 eShopID() const noexcept {return GetHeader().GeteShopID();}
		bool VerifySign() const;
		size_t TotalSize() const noexcept {return ((uptr)header - (uptr)rawticket) + sizeof(struct Header);}
		Ticket(const Ticket& other, bool mustbesigned = false) : rawticket(NULL) {
			if(mustbesigned ? !other.VerifySign() : false)
				throw std::invalid_argument("Ticket is not properly signed.");
			*this = other;
		}
		Ticket(const void* ptr, size_t ptrlen, bool mustbesigned = false);
		~Ticket() noexcept;
	};
}
#endif