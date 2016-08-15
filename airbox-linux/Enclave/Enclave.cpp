/**
*   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>

#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

//================ Hashmap implementation ======================
#define MAP_MISSING -3  /* No such element */
#define MAP_FULL -2 	/* Hashmap is full */
#define MAP_OMEM -1 	/* Out of Memory */
#define MAP_OK 0 	/* OK */

//#define ENABLE_DEBUG 0
int debug = 1;

#define RAU
//#define SES
typedef void *any_t;
typedef int (*PFany)(any_t, any_t);
typedef any_t map_t;
map_t hashmap_new();
int hashmap_iterate(map_t in, PFany f, any_t item);
int hashmap_put(map_t in, char* key, any_t value);
int hashmap_get(map_t in, char* key, any_t *arg);
int hashmap_remove(map_t in, char* key);
int hashmap_get_one(map_t in, any_t *arg, int remove);
void hashmap_free(map_t in);
int hashmap_length(map_t in);
int hashmap_keys(map_t in, char** keys, int* klen);
/* We need to keep keys and values */
typedef struct _hashmap_element{
	char* key;
	int in_use;
	any_t data;
} hashmap_element;

/* A hashmap has some maximum size and current size,
 * as well as the data to hold. */
typedef struct _hashmap_map{
	int table_size;
	int size;
	hashmap_element *data;
} hashmap_map;

typedef struct data_struct_s
{
    char key_string[1000];
    char *value_string;
} data_struct_t;

char global_var = 'a';
map_t mymap;
char current_request[100];

#define INITIAL_SIZE (256)
#define MAX_CHAIN_LENGTH (8)
static unsigned long crc32_tab[] = {
      0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
      0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
      0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
      0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
      0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
      0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
      0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
      0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
      0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
      0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
      0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
      0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
      0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
      0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
      0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
      0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
      0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
      0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
      0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
      0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
      0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
      0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
      0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
      0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
      0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
      0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
      0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
      0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
      0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
      0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
      0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
      0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
      0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
      0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
      0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
      0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
      0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
      0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
      0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
      0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
      0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
      0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
      0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
      0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
      0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
      0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
      0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
      0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
      0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
      0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
      0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
      0x2d02ef8dL
   };

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

sgx_ecc_state_handle_t ecc_handle;
sgx_ec256_private_t private_key;
sgx_ec256_public_t public_key;

// hardcoded session key
unsigned char session_key[16] = "ABCDEFGHIJKLMNO"; 
#define AES_LENGTH 16

void encryption(unsigned char *key, unsigned char *input, unsigned char *output, int length)
{
	mbedtls_aes_context aes;
	unsigned char iv[16] = "random";

        printf("encrpytion setkey\n");
	// TODO: check key length
	mbedtls_aes_setkey_enc(&aes, key, 256);
        printf("encrpytion\n");
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, input, output);
}

void decryption(unsigned char *key, unsigned char *input, unsigned char *output, int length)
{
	mbedtls_aes_context aes;
	unsigned char iv[16] = "random";

        printf("decrpytion setkey\n");
    // TODO: check key length
	mbedtls_aes_setkey_dec(&aes, key, 256);
        printf("decrpytion\n");
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iv, input, output);
}

#define MAX_SIZE_LEN 128
#define MAX_SIZE_ARG 32
#define MAX_SIZE_PATH 128 // Set manaully

#if 0
void airbox_sgx_attest()
{
	    // Attestation
    if(debug) printf("-----Attestation-----\n");
    targetinfo_t t;
    unsigned char report_data[64] = "User Data";
    report_t report;

    memset(&t, 0, sizeof(targetinfo_t));

    sgx_report(&t, report_data, &report);

    unsigned char quote[640]; // 384 report + 256 signature
    memset(quote, 0, 512);
    memcpy(quote, (unsigned char *)&report, 384);
    int k;
	if(debug)
	{
    	printf("report: ");
    	for (k = 0; k < 384; k++)
      		printf("%02X", quote[k]);
    	printf("\n");
	}

    pk_context ctx;
    pk_init(&ctx);
    pk_parse_key(&ctx, (unsigned char *)quoting_key,
                 strlen(quoting_key), NULL, 0);
    rsa_set_padding(pk_rsa(ctx), RSA_PKCS_V15, POLARSSL_MD_SHA256);

    unsigned char hash[32];
    sha256(quote, 384, hash, 0);
    rsa_pkcs1_sign(pk_rsa(ctx), NULL, NULL, RSA_PRIVATE,
                   POLARSSL_MD_SHA256, 32, hash, quote + 384);
	if(debug)
	{
    	printf("sign: ");
    	for (k = 0; k < 256; k++)
      		printf("%02X", quote[k + 384]);
    	printf("\n");
	}
}
#endif

void get(char *key, size_t klen, char *value, size_t vlen)
{
    printf(">> GET\n");
    if (debug) printf("key length: %d\n", klen);
		
    //TODO: get session key
    //attest(); 
    // decrypt using session key
    char *preq = NULL;
#if defined(RAU)
    preq = (char*)malloc(klen);
    decryption(session_key, (unsigned char *)key, (unsigned char *)preq, klen);
    if(debug) {
        printf("Decrypted using session key\n");
        int i = 0;
        printf("Key in plain text: %s\n", preq);
        while(i < klen)
            printf("%c",preq[i++]);
        printf("\n--------------\n");
    }
#else
    //memcpy(preq,ereq,atoi(eklen));
    //preq = ereq;
#endif
    //TODO: Look up logic
    char *path; // = "efstate.rd";
	if (mymap == NULL)
        mymap = hashmap_new();
    int found = hashmap_get(mymap, preq, (any_t*)(&path));

    if (found == MAP_MISSING) {
	    memset(value, 0, vlen);
        if(debug) printf("Not found in hashmap\n");
            //sgx_exit(NULL);
    } else {
		if (vlen < strlen(path) + 1) {
            printf("The buffer is too small.\n");
            return;
        }
		memset(path, 0, vlen);
		memcpy(value, path, strlen(path) + 1);
        if(debug) printf("Found path: %s\n", path);
    }

    printf("<< GET\n");
}


void complete_get(char *fcont, size_t flen, char *retval, size_t retvlen)
{
    int i = 0;
    printf(">> Complete GET\n");
    if(debug) printf("Enclave flen: %d \n", flen);

	if(debug) {
        printf("Enclave read: %s \n", fcont);
        while(i < flen)
            printf("%c", fcont[i++]);
        printf("\n");
    }
    //TODO: get sealing key

    char *dfcont = NULL; //(char*)malloc(atoi(flen));
#if defined(SES)
    dfcont = (char*)malloc(atoi(flen));
    keyrequest_t keyreq;
    unsigned char *seal_key;
    keyreq.keyname = SEAL_KEY;
    seal_key = memalign(128, 16);
    //if(debug) 
	    printf("Trying to het sealing key\n");
    sgx_getkey(&keyreq, seal_key);
    //if(debug) 
	printf("Got sealing key: %s.\n",seal_key);
    //TODO: decrypt using sealing key

    decryption(seal_key,fcont,dfcont,atoi(flen));
    //if(debug) 
        printf("Decrypted using sealing key\n");
#else
    //memcpy(dfcont, fcont,atoi(flen));
    dfcont = fcont;
#endif
    //TODO: EF logic

    //Encrypt using session key
    char *efcont = NULL;  //(char*)malloc(atoi(flen));
#if defined(RAU) 
    efcont = (char*) malloc(flen);
    encryption(session_key, (unsigned char *)dfcont, (unsigned char *)efcont, flen);
	if(debug) {
        i = 0;
        printf("Encrypted response: \n");
        while(i < flen)
            printf("%x", efcont[i++]);
            printf("\n");
    }
    if(debug) printf("Encrypted using sesison key\n");
#else
    //memcpy(efcont,fcont,atoi(flen));
    efcont = fcont;
#endif

    if (debug) printf("Encryption done.\n");

    // write encrypted content to host
    if(debug) {
        printf("Enclave sent message: %d\n",flen);
        i = 0;
        while(i < flen)
            printf("%x", efcont[i++]);
            printf("\n");
        }
        if (retvlen < flen) {
		    printf("retval buffer is too small.\n");
		    return;
    }
    memset(retval, 0, retvlen);
	memcpy(retval, efcont, flen);

    printf("<< Complete GET\n");
}

void put(char *ereq, size_t eklen, char *value, size_t vlen)
{
    printf(">> PUT\n");
    if (debug) printf("key length: %d\n", eklen);

    //TODO: get session key
    //airvox_sgx_attest(); 
    // decrypt using session key
    char *preq = NULL;
#if defined(RAU)
    preq = (char*) malloc(eklen);
    decryption(session_key, (unsigned char *)ereq, (unsigned char *)preq, eklen);
    if(debug) printf("Decrypted using sesison key\n");
#else
    //memcpy(preq,ereq,atoi(eklen));
    //preq = ereq;
#endif
    //FIXME: Add entry to hashmap & generate a new file name
    char *wpath = "efstat.wr";
    //char *wpath = malloc(MAX_SIZE_PATH);// = "efstat.wr";
    //sprintf(wpath,"efstat_%s.wr", preq);
    if (mymap == NULL)
        mymap = hashmap_new();

    int hres = hashmap_put(mymap, preq, (any_t)(wpath));
    if (hres != MAP_OK) {
        printf("Error adding to hashmap\n");
    }
    if (debug) printf("Added to hashmap key: %s, val: %s\n", preq, wpath);

    if (vlen < strlen(wpath) + 1) {
        printf("buffer is too small\n");
        return;
    }
    memset(value, 0, vlen);
    memcpy(value, wpath, strlen(wpath) + 1);

    //printf("Path to be written to: %s - %s\n",wpath, preq);
    printf("<< PUT\n");
}

void complete_put(char *eval, size_t vlen, char *retval, size_t retvlen)
{
    printf(">> Complete PUT\n");

	if (debug) printf("Read encrypted: %d\n", vlen);

	// decrypt using session key
    char *pval = NULL;
#if defined(RAU)
    //TODO: get session key
    //airbox_sgx_attest(); 
    pval = (char*) malloc(vlen);
    decryption(session_key, (unsigned char *)eval, (unsigned char *)pval, vlen);
	if (debug) {
       /* printf("Val in plain text: %s\n", pval);
       int i = 0;
       while(i < vlen)
           printf("%c", pval[i++]);
       printf("\n");*/
    }
    if(debug) printf("Decrypted using sesison key\n");
#else
    //memcpy(pval,eval,vlen);
    //pval = eval;
#endif
    if (debug) 
    printf("Decryption done.\n");
    char *efcont = NULL;
#if defined(SES)
    efcont =(char*)malloc(vlen);
    keyrequest_t keyreq;
    unsigned char *seal_key;

    keyreq.keyname = SEAL_KEY;
    seal_key = memalign(128, 16);
	printf("Getting sealing key.\n");
    sgx_getkey(&keyreq, seal_key);
	//if(debug)
		printf("Got sealing key: %s.\n",seal_key);

    encryption(seal_key, pval, efcont,vlen);
    //if(debug) 
		printf("Encrypted using sealing key\n");
#else
    // memcpy(efcont, pval, vlen);
    efcont = pval;
#endif
    printf("Sealing encryption done.\n");
    // write encrypted content to host

    if (retvlen < vlen) {
        printf("buffer is too small.\n");
        return;
	}
	memset(retval, 0, retvlen);
	memcpy(retval, efcont, vlen);
    if(debug) printf("File to be stored.\n");

    printf("<< Complete PUT\n");
}

#if 0
void rem()
{
	
	 printf(">> REMOVE\n");
     char eklen[MAX_SIZE_LEN];
     sgx_getarg(1, eklen, MAX_SIZE_LEN);
     // read actual encrypted key/req
     char *ereq = (char*) malloc(atoi(eklen));
     sgx_enclave_read(ereq, atoi(eklen));
     if(debug) printf("Request: %s\n", ereq);

     //TODO: get session key
     //attest(); 
     // decrypt using session key
     char *preq = NULL;//(char*)malloc(atoi(eklen));
#if defined(RAU)
        preq = (char*)malloc(atoi(eklen));
        decryption(session_key, ereq,preq,atoi(eklen));
        if(debug) printf("Decrypted using session key\n");
#else
        //memcpy(preq,ereq,atoi(eklen));
        preq = ereq;
#endif

        //TODO: Look up logic
        char *path;// = "efstate.rd";
        if(mymap == NULL)
            mymap = hashmap_new();
        int found = hashmap_get(mymap, preq, (any_t*)(&path));
        if(found == MAP_MISSING)
        {
            char res[MAX_SIZE_LEN] = { 0 };
            int zero = 0;
            sprintf(res,"%d",zero);
            sgx_enclave_write(res,MAX_SIZE_LEN);
            if(debug) printf("Not found in hashmap\n");
        }
        else
        {
            sgx_enclave_write(path,MAX_SIZE_PATH);
			hashmap_remove(mymap, preq);
            if(debug) printf("Removed path: %s\n",path);
        }
        printf("<< REMOVE\n");

}

void len()
{
	printf(">> LEN\n");
	int ret = 0;
	char res[MAX_SIZE_LEN] = { 0 };
	
	ret = hashmap_length(mymap);
		
	sprintf(res,"%d", ret);
	sgx_setretval(0, res, MAX_SIZE_LEN);
	printf("<< LEN\n");
}

void keys()
{
	printf(">> KEYS\n");
	int klen = 0;
	char klens[MAX_SIZE_LEN];
	char* keys = NULL;
	
	if(hashmap_keys(mymap, &keys, &klen) != MAP_OK)
	{
		printf("Issue getting keys from hashmap\n");
	}


	if(debug)
	{
		int i = 0;
		while(i < klen)
			putc(keys[i++],stdout);
		printf("%s\n", keys);
	}
	
	char *ekeys = NULL;
	int eklen = 0;
	int aklen = 0;
	char* akeys = NULL;
#if defined(RAU)
	aklen = klen + (AES_LENGTH - (klen % AES_LENGTH));
	akeys = malloc(aklen);
	memset(akeys, 0, aklen);
	memcpy(akeys,keys,klen);
	if(debug)
	{
		printf("------------%d \n", aklen);
		int i = 0;
		while(i < aklen)
			putc(akeys[i++],stdout);
		//printf("%s\n", keys);
		printf("------------\n");
	}
	eklen = aklen;
	ekeys = malloc(eklen);
	encryption(session_key, akeys, ekeys, eklen);
#else
	ekeys = keys;
	eklen = klen;
#endif

	sprintf(klens,"%d", eklen);
	if(debug) 
		printf("%d\n", eklen);
    sgx_setretval(0, klens, MAX_SIZE_LEN);

	sgx_enclave_write(ekeys,eklen);	
	printf("<< KEYS\n");
}
#endif

/*
 * Return an empty hashmap, or NULL on failure.
 */
map_t hashmap_new() {
	hashmap_map* m = (hashmap_map*) malloc(sizeof(hashmap_map));
	if(!m) goto err;

	m->data = (hashmap_element*) calloc(INITIAL_SIZE, sizeof(hashmap_element));
	if(!m->data) goto err;

	m->table_size = INITIAL_SIZE;
	m->size = 0;

	return m;
	err:
		if (m)
			hashmap_free(m);
		return NULL;
}

/* Return a 32-bit CRC of the contents of the buffer. */

unsigned long crc32(const unsigned char *s, unsigned int len)
{
  unsigned int i;
  unsigned long crc32val;
  
  crc32val = 0;
  for (i = 0;  i < len;  i ++)
    {
      crc32val =
	crc32_tab[(crc32val ^ s[i]) & 0xff] ^
	  (crc32val >> 8);
    }
  return crc32val;
}

/*
 * Hashing function for a string
 */
unsigned int hashmap_hash_int(hashmap_map * m, char* keystring){

    unsigned long key = crc32((unsigned char*)(keystring), strlen(keystring));

	/* Robert Jenkins' 32 bit Mix Function */
	key += (key << 12);
	key ^= (key >> 22);
	key += (key << 4);
	key ^= (key >> 9);
	key += (key << 10);
	key ^= (key >> 2);
	key += (key << 7);
	key ^= (key >> 12);

	/* Knuth's Multiplicative Method */
	key = (key >> 3) * 2654435761;

	return key % m->table_size;
}

/*
 * Return the integer of the location in data
 * to store the point to the item, or MAP_FULL.
 */
int hashmap_hash(map_t in, char* key){
	int curr;
	int i;

	/* Cast the hashmap */
	hashmap_map* m = (hashmap_map *) in;

	/* If full, return immediately */
	if(m->size >= (m->table_size/2)) return MAP_FULL;

	/* Find the best index */
	curr = hashmap_hash_int(m, key);

	/* Linear probing */
	for(i = 0; i< MAX_CHAIN_LENGTH; i++){
		if(m->data[curr].in_use == 0)
			return curr;

		if(m->data[curr].in_use == 1 && (strcmp(m->data[curr].key,key)==0))
			return curr;

		curr = (curr + 1) % m->table_size;
	}

	return MAP_FULL;
}

/*
 * Doubles the size of the hashmap, and rehashes all the elements
 */
int hashmap_rehash(map_t in){
	int i;
	int old_size;
	hashmap_element* curr;

	/* Setup the new elements */
	hashmap_map *m = (hashmap_map *) in;
	hashmap_element* temp = (hashmap_element *)
		calloc(2 * m->table_size, sizeof(hashmap_element));
	if(!temp) return MAP_OMEM;

	/* Update the array */
	curr = m->data;
	m->data = temp;

	/* Update the size */
	old_size = m->table_size;
	m->table_size = 2 * m->table_size;
	m->size = 0;

	/* Rehash the elements */
	for(i = 0; i < old_size; i++){
        int status;

        if (curr[i].in_use == 0)
            continue;
            
		status = hashmap_put(m, curr[i].key, curr[i].data);
		if (status != MAP_OK)
			return status;
	}

	free(curr);

	return MAP_OK;
}

/*
 * Add a pointer to the hashmap with some key
 */
int hashmap_put(map_t in, char* key, any_t value){
	int index;
	hashmap_map* m;

	/* Cast the hashmap */
	m = (hashmap_map *) in;

	/* Find a place to put our value */
	index = hashmap_hash(in, key);
	while(index == MAP_FULL){
		if (hashmap_rehash(in) == MAP_OMEM) {
			return MAP_OMEM;
		}
		index = hashmap_hash(in, key);
	}

	/* Set the data */
	m->data[index].data = value;
	m->data[index].key = key;
	m->data[index].in_use = 1;
	m->size++; 
	if(debug) printf("hashmap entry key: %s val: %s\n",key,(char*)value);
	return MAP_OK;
}

/*
 * Get your pointer out of the hashmap with a key
 */
int hashmap_get(map_t in, char* key, any_t *arg){
	int curr;
	int i;
	hashmap_map* m;

	/* Cast the hashmap */
	m = (hashmap_map *) in;

	/* Find data location */
	curr = hashmap_hash_int(m, key);

	/* Linear probing, if necessary */
	for(i = 0; i<MAX_CHAIN_LENGTH; i++){

        int in_use = m->data[curr].in_use;
        if (in_use == 1){
            if (strcmp(m->data[curr].key,key)==0){
                *arg = (m->data[curr].data);
                return MAP_OK;
            }
		}

		curr = (curr + 1) % m->table_size;
	}

	*arg = NULL;

	/* Not found */
	return MAP_MISSING;
}

int hashmap_keys(map_t in, char** keys, int* klen)
{
	int i;

    /* Cast the hashmap */
    hashmap_map* m = (hashmap_map*) in;
	char *rlist = NULL;
	char *tlist = NULL;

    /* On empty hashmap, return immediately */
    if (hashmap_length(m) <= 0)
        return MAP_MISSING;

	 /* Linear probing */
	int curlen = 0;
    for(i = 0; i< m->table_size; i++)
	{
        if(m->data[i].in_use != 0) 
		{
			tlist = (char *)malloc(curlen + strlen(m->data[i].key)+2);
			if(!tlist)
			{
				printf("Unable to allocate memory\n");
				return MAP_OMEM;
			}
			//copy to temp
			if(rlist) 
			{
				memcpy(tlist, rlist, curlen);
			}
			//free returnable list
			if(rlist) free(rlist);
			// append current to temp
			memcpy(tlist+ curlen, m->data[i].key, strlen(m->data[i].key));
			// swap rlist & tlist
			rlist = tlist;
			rlist[curlen + strlen(m->data[i].key)] = '\n';
			rlist[curlen + strlen(m->data[i].key)+1] = '\0';
			if(debug) printf("%s\n",rlist);
			curlen += (strlen(m->data[i].key) + 2);
		    if(debug) printf("curlen: %d\n", curlen);
         }
    }
	i = 0;
    if(debug)
	while(i < curlen)
		printf("%x", rlist[i++]);
    printf("\n");

	*klen = curlen;
	*keys = rlist;

    return MAP_OK;
}

/*
 * Iterate the function parameter over each element in the hashmap.  The
 * additional any_t argument is passed to the function as its first
 * argument and the hashmap element is the second.
 */
int hashmap_iterate(map_t in, PFany f, any_t item) {
	int i;

	/* Cast the hashmap */
	hashmap_map* m = (hashmap_map*) in;

	/* On empty hashmap, return immediately */
	if (hashmap_length(m) <= 0)
		return MAP_MISSING;	

	/* Linear probing */
	for(i = 0; i< m->table_size; i++)
		if(m->data[i].in_use != 0) {
			any_t data = (any_t) (m->data[i].data);
			int status = f(item, data);
			if (status != MAP_OK) {
				return status;
			}
		}

    return MAP_OK;
}

/* Remove an element with that key from the map
 */
int hashmap_remove(map_t in, char* key){
	int i;
	int curr;
	hashmap_map* m;

	/* Cast the hashmap */
	m = (hashmap_map *) in;

	/* Find key */
	curr = hashmap_hash_int(m, key);

	/* Linear probing, if necessary */
	for(i = 0; i<MAX_CHAIN_LENGTH; i++){

        int in_use = m->data[curr].in_use;
        if (in_use == 1){
            if (strcmp(m->data[curr].key,key)==0){
                /* Blank out the fields */
                m->data[curr].in_use = 0;
                m->data[curr].data = NULL;
                m->data[curr].key = NULL;

                /* Reduce the size */
                m->size--;
                return MAP_OK;
            }
		}
		curr = (curr + 1) % m->table_size;
	}

	/* Data not found */
	return MAP_MISSING;
}

/* Deallocate the hashmap */
void hashmap_free(map_t in){
	hashmap_map* m = (hashmap_map*) in;
	free(m->data);
	free(m);
}

/* Return the length of the hashmap */
int hashmap_length(map_t in){
	hashmap_map* m = (hashmap_map *) in;
	if(m != NULL) return m->size;
	else return 0;
}

void test_init()
{
	sgx_status_t status;
	printf("[Enclave] test_init\n");

	if ( (status = sgx_ecc256_open_context(&ecc_handle)) != SGX_SUCCESS) {
		printf("ecc init failed\n");
	}

    if ( (sgx_ecc256_create_key_pair(&private_key, &public_key, ecc_handle)) != SGX_SUCCESS) {
	    printf("ecc create key pair failed\n");
	}

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	unsigned char key[32];

	char *pers = "aes generate key";
	int ret;
	int i;

	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)pers, strlen(pers))) != 0) {
	    printf("drbg_seed failed\n");
		return;
	}

	if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, 32)) != 0) {
		printf("drbg_random failed\n");
		return;
	}

	printf("key:");
	for (i = 0; i < 32; i++)
		printf("%X", key[i]);
	printf("\n");

	mbedtls_aes_context aes;

	unsigned char iv[16] = "random";

	unsigned char input[128] = "hello enclave";
	unsigned char output[128];

	printf("target: %s\n", input);

	memset(output, 0, 128);

	encryption(key, input, output, 128);

	printf("output: %s\n", output);
	for (i = 0; i < 128; i++)
		printf("%X", output[i]);
	printf("\n");

	unsigned char plain[128] = "";
	decryption(key, output, plain, 128);

	printf("decrypt: %s\n", plain);

	printf("[Enclave] Init done\n");
}
