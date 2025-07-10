
/*
 * aes.h
 *
 *  Created on: May 20, 2025
 *      Author: 15226
 */

#ifndef AES_H_
#define AES_H_
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef StandAES
#define false	0
#define true	1

#define _SURPPORT_DECRYPT_	false


typedef struct{
    uint32_t eK[44], dK[44];    // encKey, decKey
    int Nr; // 10 rounds
}AesKey;



#define BLOCKSIZE 16  //AES-128分组长度为16字节

typedef unsigned char uint8_t;
// uint8_t y[4] -> uint32_t x
#define LOAD32H(x, y) \
  do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
             ((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

// uint32_t x -> uint8_t y[4]
#define STORE32H(x, y) \
  do { (y)[0] = (uint8_t)(((x)>>24) & 0xff); (y)[1] = (uint8_t)(((x)>>16) & 0xff);   \
       (y)[2] = (uint8_t)(((x)>>8) & 0xff); (y)[3] = (uint8_t)((x) & 0xff); } while(0)

// 从uint32_t x中提取从低位开始的第n个字节
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* used for keyExpansion */
// 字节替换然后循环左移1位
#define MIX(x) ((((unsigned long)S[BYTE(x, 2)] << 24) & 0xff000000) ^ (((unsigned long)S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
                (((unsigned long)S[BYTE(x, 0)] << 8) & 0xff00) ^ ((unsigned long)S[BYTE(x, 3)] & 0xff))

// uint32_t x循环左移n位
#define ROF32(x, n)  (((x) << (n)) | ((x) >> (32-(n))))
// uint32_t x循环右移n位
#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32-(n))))

#if (_SURPPORT_DECRYPT_ == true)
int invSubBytes(uint8_t (*state)[4]);
int invShiftRows(uint8_t (*state)[4]);
int invMixColumns(uint8_t (*state)[4]);
int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len);
#endif

int loadStateArray(uint8_t (*state)[4], const uint8_t *in);
int storeStateArray(uint8_t (*state)[4], uint8_t *out);
int keyExpansion(const uint8_t *key, uint32_t keyLen, AesKey *aesKey);
int addRoundKey(uint8_t (*state)[4], const uint32_t *key);
int subBytes(uint8_t (*state)[4]);
int shiftRows(uint8_t (*state)[4]);
uint8_t GMul(uint8_t u, uint8_t v);
int mixColumns(uint8_t (*state)[4]);
int aesEncrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *pt, uint8_t *ct, uint32_t len);

void xor_128(unsigned char *a, unsigned char *b, unsigned char *out);
void leftshift_onebit(unsigned char *input,unsigned char *output);
void generate_subkey(unsigned char *key, unsigned char *K1, unsigned char *K2);
void padding ( unsigned char *lastb, unsigned char *pad, int length );
void AES_CMAC ( unsigned char *key, unsigned char *input, int length,unsigned char *mac );
void AES_128_CMAC_Test(void);

extern unsigned char key[16];
extern unsigned char Result[16];
extern unsigned char seed[16];
extern unsigned char SigVal[16];
extern unsigned char AES_Flag;

#endif
#endif /* AES_H_ */
