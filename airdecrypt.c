/*
 * Copyright (c) 2016 Steve White
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <CommonCrypto/CommonCrypto.h>
#include <libkern/OSByteOrder.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define countof(a) (sizeof(a) / sizeof((a)[0]))

#define CHUNK_SIZE 0x8000
#define KEY_LENGTH 16

typedef struct {
	char magic[15];
	uint8_t unknownA;
	
	uint32_t model;
	uint16_t version;
	
	uint8_t unknownB[5];
	
	uint8_t flags;
	uint8_t unknownC[4];
} firmware_header_t;

typedef struct {
	uint32_t model;
	uint8_t key[KEY_LENGTH];
} model_key_t;

model_key_t model_keys[] = {
	// AirPort Express 802.11g
	// { .model = 102, .key = {}},
	
	// AirPort Extreme 802.11n (1st Generation)
	// { .model = 104, .key = {}},
	
	// M91: AirPort Extreme 802.11n (2nd Generation)
	{ .model = 105, .key = {0x87,0xf5,0x2f,0x57,0xc5,0x73,0xe8,0x74,0x99,0xb6,0xd6,0x9c,0x8e,0x4b,0xcb,0x8b}},
	
	// AirPort Time Capsule 802.11n (1st Generation)
	// { .model = 106, .key = {}},
	
	// M48: AirPort Express 802.11n (1st Generation)
	{ .model = 107, .key = {0x52,0x49,0xc3,0x51,0x02,0x8b,0xf1,0xfd,0x2b,0xd1,0x84,0x9e,0x28,0xb2,0x3f,0x24}},
	
	// K10: AirPort Extreme 802.11n (3rd Generation)
	{ .model = 108, .key = {0xbb,0x7d,0xeb,0x09,0x70,0xd8,0xee,0x2e,0x00,0xfa,0x46,0xcb,0x1c,0x3c,0x09,0x8e}},
	
	// AirPort Time Capsule 802.11n (2nd Generation)
	// { .model = 109, .key = {}},
	
	// AirPort Time Capsule 802.11n (3rd Generation)
	// { .model = 113, .key = {}},
	
	// K10A: AirPort Extreme 802.11n (4th Generation)
	{ .model = 114, .key = {0xa6,0x6e,0x26,0x3e,0x7b,0x75,0x12,0x42,0xac,0x7f,0xa0,0xc9,0x09,0x51,0xed,0x08}},
	
	// K31: AirPort Express 802.11n (2nd Generation)
	{ .model = 115, .key = {0x10,0x75,0xe8,0x06,0xf4,0x77,0x0c,0xd4,0x76,0x3b,0xd2,0x85,0xa6,0x4e,0x91,0x74}},
	
	// K30B: AirPort Time Capsule 802.11n (4th Generation)
	{ .model = 116, .key = {0x9d,0x12,0x59,0xee,0x89,0xf2,0x8a,0x2c,0xcf,0xa6,0x46,0x97,0xad,0xbb,0x41,0x93}},
	
	// K10B: AirPort Extreme 802.11n (5th Generation)
	{ .model = 117, .key = {0x74,0x11,0x9d,0x51,0x82,0xc7,0xa3,0x17,0xdb,0x00,0x26,0xe4,0x9e,0xfd,0xe7,0x9a}},
	
	// 119 AirPort Time Capsule 802.11ac
 	{ .model = 119, .key = {0xb1,0x99,0x37,0xdd,0xcb,0x78,0xb3,0xf1,0x51,0xe4,0xe0,0xb4,0x81,0x98,0xe6,0xa7}},
	
	// J28E: AirPort Extreme 802.11ac
	{ .model = 120, .key = {0x68,0x8c,0xdd,0x3b,0x1b,0x6b,0xdd,0xa2,0x07,0xb6,0xce,0xc2,0x73,0x52,0x92,0xd2}},
};

int decryptImageToFileNamed(const uint8_t *image, uint32_t length, const char *fileName) {
	uint32_t offset = 0;
	
	firmware_header_t *header = (firmware_header_t *)image;
	if (strcasecmp(header->magic, "APPLE-FIRMWARE") != 0) {
		fprintf(stderr, "bad magic in header\n");
		return -1;
	}
	
	offset = sizeof(firmware_header_t);
	length -= 4; // trailing checksum
	
	if (header->flags != 0x02) {
		// not an encrypted image... check to see if there is a
		// nested header.
		header = (firmware_header_t *)(image + sizeof(firmware_header_t));
		if (strcasecmp(header->magic, "APPLE-FIRMWARE") != 0) {
			header = (firmware_header_t *)image;
		}
		else {
			offset += sizeof(firmware_header_t);
			length -= 4; // trailing checksum
		}
	}
	
	uint32_t model = OSSwapHostToBigInt32(header->model);
	uint8_t *key = NULL;
	if (header->flags == 0x02) {
		// Encrypted image, see if we have the key...
		for (int i=0; i<countof(model_keys); i++) {
			if (model_keys[i].model == model) {
				key = model_keys[i].key;
				break;
			}
		}
		
		if (key == NULL) {
			fprintf(stderr, "Couldn't find decryption key for model %i\n", model);
			return -1;
		}
	}
	
	int fpOut = -1;
	if (fileName == NULL) {
		fpOut = STDOUT_FILENO;
	}
	else {
		fpOut = open(fileName, O_CREAT | O_TRUNC | O_RDWR, 0664);
		if (fpOut < 0) {
			fprintf(stderr, "%s: %s\n", fileName, strerror(errno));
			return -1;
		}
	}
	
	if (key == NULL) {
		// Unencrypted firmware, we can just write it back out
		// minus the header and checksum...
		write(fpOut, image + offset, length - offset);
		goto out;
	}
	
	uint8_t derivedKey[KEY_LENGTH];
	for (int i=0; i<KEY_LENGTH; i++) {
		derivedKey[i] = key[i] ^ (i + 25);
	}
	
	uint8_t *outBuffer = calloc(CHUNK_SIZE, sizeof(uint8_t));
	if (outBuffer == NULL) {
		fprintf(stderr, "calloc failed: %s\n", strerror(errno));
		return -1;
	}
	
	while (offset < length) {
		uint32_t chunkSize = MIN(CHUNK_SIZE, length - offset);
		uint8_t plaintextLen = (chunkSize % 16);
		chunkSize -= plaintextLen;
		
		CCCrypt(kCCDecrypt,
				kCCAlgorithmAES128,
				0,
				derivedKey,
				KEY_LENGTH,
				image,
				image + offset,
				chunkSize,
				outBuffer,
				CHUNK_SIZE,
				NULL);
		
		write(fpOut, outBuffer, chunkSize);
		offset += chunkSize;
		
		if (plaintextLen > 0) {
			write(fpOut, image + offset, plaintextLen);
			offset += plaintextLen;
		}
	}
	
	free(outBuffer);
	
out:
	if (fpOut != STDOUT_FILENO) {
		close(fpOut);
	}
	
	return 0;
}

int main(int argc, const char * argv[]) {
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "usage: %s <input basebinary> [output]\n", argv[0]);
		return -1;
	}
	
	int fp = open(argv[1], O_RDONLY);
	if (fp < 0) {
		fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
		return -1;
	}
	
	off_t filesize = lseek(fp, 0, SEEK_END);
	lseek(fp, 0, SEEK_SET);
	int result;
	const uint8_t *image = mmap(0, filesize, PROT_READ, MAP_SHARED, fp, 0);
	if (image == NULL) {
		fprintf(stderr, "Couldn't mmap: %s\n", strerror(errno));
		result = -1;
	}
	else {
		result = decryptImageToFileNamed(image, (uint32_t)filesize, (argc == 3 ? argv[2] : NULL));

		munmap((uint8_t *)image, filesize);
	}
	
	close(fp);
	return result;
}
