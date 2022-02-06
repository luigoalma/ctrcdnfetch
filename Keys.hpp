#pragma once
#include "types.h"

namespace NintendoData {
	namespace KeyUtils {
		namespace Storage {
			enum KeyType {
				KeyX = 0,
				KeyY,
				KeyNormal
			};
			bool ReloadStorage();
			u8* GetKey(u8* outkey, int keyslot, KeyType type = KeyX, bool retail = true);
			u8* GetCommonKey(u8* outkey, int index, bool retail = true);
			inline static u8* GetKeyX(u8* outkey, int keyslot, bool retail = true) {return GetKey(outkey, keyslot, KeyX, retail);}
			inline static u8* GetKeyY(u8* outkey, int keyslot, bool retail = true) {return GetKey(outkey, keyslot, KeyY, retail);}
			inline static u8* GetKeyNormal(u8* outkey, int keyslot, bool retail = true) {return GetKey(outkey, keyslot, KeyNormal, retail);}
		}
		bool TWLScrambler(u8* outnormal, const u8* KeyX, const u8* KeyY);
		bool CTRScrambler(u8* outnormal, const u8* KeyX, const u8* KeyY);
		inline static bool Scrambler(u8* outnormal, int keyslotX, const u8* keyY, bool retail = true) {
			u8 key[16];
			if(keyslotX < 4) return TWLScrambler(outnormal, Storage::GetKeyX(key, keyslotX, retail), keyY);
			else return CTRScrambler(outnormal, Storage::GetKeyX(key, keyslotX, retail), keyY);
		}
		inline static bool Scrambler(u8* outnormal, const u8* keyX, int keyslotY, bool retail = true) {
			u8 key[16];
			if(keyslotY < 4) return TWLScrambler(outnormal, keyX, Storage::GetKeyY(key, keyslotY, retail));
			else return CTRScrambler(outnormal, keyX, Storage::GetKeyY(key, keyslotY, retail));
		}
		inline static bool ScrambleCommon(u8* outnormal, int index, bool retail = true) {
			u8 keys[2][16];
			return CTRScrambler(outnormal, Storage::GetKeyX(keys[0], 0x3D, retail), Storage::GetCommonKey(keys[1], index, retail));
		}
		void SeedKeyY(u8* keyY, const u8* seed);
	}
	class AESEngine {
	public:
		enum Modes {
			//CCM = 0,
			CTR = 1,
			CBC,
			ECB
		};
		class CrypterContext {
		private:
			void* context;
			u8 _key[16];
			Modes _mode;
			bool _encrypt;
		public:
			void ResetIV(const u8* iv);
			void Cipher(u8* dataout, const u8* datain, int length);
		private:
			CrypterContext(Modes mode, const u8* key, const u8* iv, bool encrypt);
		public:
			~CrypterContext();
			friend AESEngine;
		};
	private:
		u8 (*keyslots)[3][64][16];
		bool retail;
	public:
		AESEngine& operator=(AESEngine&&);
		AESEngine& operator=(const AESEngine&);
		bool ReloadFromKeyStorage();
		void SetRetail(bool retail) {this->retail = retail;}
		void Cipher(Modes mode, int keyslot, const u8* iv, u8* out, const u8* data, int length, bool encrypt);
		void Encrypt(Modes mode, int keyslot, const u8* iv, u8* out, const u8* data, int length) {
			Cipher(mode, keyslot, iv, out, data, length, true);
		}
		void Decrypt(Modes mode, int keyslot, const u8* iv, u8* out, const u8* data, int length) {
			Cipher(mode, keyslot, iv, out, data, length, false);
		}
		void CTREncrypt(int keyslot, const u8* iv, u8* out, const u8* data, int length) {
			Encrypt(CTR, keyslot, iv, out, data, length);
		}
		void CTRDecrypt(int keyslot, const u8* iv, u8* out, const u8* data, int length) {
			Decrypt(CTR, keyslot, iv, out, data, length);
		}
		void CBCEncrypt(int keyslot, const u8* iv, u8* out, const u8* data, int length) {
			Encrypt(CBC, keyslot, iv, out, data, length);
		}
		void CBCDecrypt(int keyslot, const u8* iv, u8* out, const u8* data, int length) {
			Decrypt(CBC, keyslot, iv, out, data, length);
		}
		void ECBEncrypt(int keyslot, u8* out, const u8* data, int length) {
			Encrypt(ECB, keyslot, nullptr, out, data, length);
		}
		void ECBDecrypt(int keyslot, u8* out, const u8* data, int length) {
			Decrypt(ECB, keyslot, nullptr, out, data, length);
		}
		AESEngine& SetKey(KeyUtils::Storage::KeyType type, int keyslot, const u8* key, const u8* seed = nullptr);
		AESEngine& SetX(int keyslot, const u8* key) {
			return SetKey(KeyUtils::Storage::KeyX, keyslot, key);
		}
		AESEngine& SetY(int keyslot, const u8* key, const u8* seed = nullptr) {
			return SetKey(KeyUtils::Storage::KeyY, keyslot, key, seed);
		}
		AESEngine& SetNormal(int keyslot, const u8* key) {
			return SetKey(KeyUtils::Storage::KeyNormal, keyslot, key);
		}
		AESEngine& SetCommon(int commonindex);
		AESEngine& SetFixedKey(int keyslot);
		AESEngine& SetZeroKey(int keyslot) {
			u8 key[16] = {0};
			return SetNormal(keyslot, key);
		}
		AESEngine& SetEncTitleKey(const u8* key, u64 titleid, int commonindex);
		CrypterContext GetCrypterContext(Modes mode, int keyslot, const u8* iv, bool encrypt);
		AESEngine(bool retail, bool keysneeded);
		AESEngine() : AESEngine(true, false) {}
		AESEngine(AESEngine&& other) {
			*this = other;
		}
		AESEngine(const AESEngine& other) {
			*this = other;
		}
		~AESEngine();
	};
}
