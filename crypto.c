#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "iot_safe.h"


#define PRINT_INFO

#define INFO(M, ...) printf("[INFO] " M "\n", ##__VA_ARGS__)
#define KEYINFO(X, Y, Z) printKeyInfo((X), (Y), (Z))

#define PRINTSW(X) printf("SW:0x%04X\n", (X));

static uint8_t channel = 0;

static iot_safe_key_t private_keys[IOT_SAFE_MAX_KEYS];
static iot_safe_key_t public_keys[IOT_SAFE_MAX_KEYS];
static iot_safe_file_t files[IOT_SAFE_MAX_FILES];
static iot_safe_secret_t secrets[IOT_SAFE_MAX_SECRETS]; 

static uint8_t private_key_number = 0;
static uint8_t public_key_number = 0;
static uint8_t file_number = 0;
static uint8_t secret_number = 0;


static uint8_t private_key_id[IOT_SAFE_ID_MAX_LENGTH];
static uint8_t private_key_id_len;
static uint8_t public_key_id[IOT_SAFE_ID_MAX_LENGTH];
static uint8_t public_key_id_len;
static uint8_t public_key[IOT_SAFE_PUBLIC_KEY_LENGTH];


char* TOHEX(const uint8_t * input, uint32_t len)
{
  static char str[1024];
  char * idx = str;

  if (2*len >= sizeof(str)) { return "failed conversion (TOHEX)"; }

  while(len--) 
  {
    idx += sprintf(idx, "%02x", *input);
    input++;
  }

  if (sizeof(str) > (idx-str)) {
    memset(idx, '\0', sizeof(str) - (idx - str));
  } 

  return str;
}

char* TOSTR(const uint8_t * input, uint32_t len)
{
  static char str[256];
  
  if (len >= sizeof(str)) { return "failed conversion (TOSTR)"; }

  memset(str, '\0', sizeof(str));
  memcpy(str, input, len);
  return str;
}

char *printKeyInfo(const char * label, const size_t len, uint8_t private)
{
  iot_safe_error_t ret;
  iot_safe_key_t key;  

  if (private)
  {
    ret = iot_safe_get_private_key_information(channel, NULL, 0, (uint8_t*) label, len, &key);
  }
  else
  {
    ret = iot_safe_get_public_key_information(channel, NULL, 0, (uint8_t*) label, len, &key);
  }

  INFO("%s Key Info", private ? "Private" : "Public");
  INFO("  Label:%s", TOSTR(key.id, key.id_length));
  INFO("  ID:%s", TOSTR(key.label, key.label_length));
  INFO("  AC:%02X", key.access_conditions);
  INFO("  STATE:%02X", key.state);
  INFO("  USAGE:%02X", key.usage);
  INFO("  CRYPTO:%02X", key.crypto_functions);
  if (key.crypto_functions & IOT_SAFE_CRYPTO_FUNCTION_SIGNATURE)
    INFO("  ALG SIG:%02X", key.algos_for_sign);
  if (key.crypto_functions & IOT_SAFE_CRYPTO_FUNCTION_SIGNATURE)
    INFO("  ALG HASH:%02X", key.algos_for_hash);
  if (key.crypto_functions & IOT_SAFE_CRYPTO_FUNCTION_KEY_AGREEMENT)
    INFO("  ALG KA:%02X", key.algos_for_key_agreement);

  return NULL;
}


uint16_t initialize(){
    return iot_safe_init(IOT_SAFE_AID, sizeof(IOT_SAFE_AID), &channel);
}

uint16_t cleanup(){
    uint16_t ret = 0x9000;
    if(channel){
        ret = iot_safe_finish(channel);
        channel=0;
    }
    return ret;
}

char* read_public_key(){
    //KEYINFO(CONTAINER_LABEL_CLIENT_OPERATIONAL1_KEY, strlen(CONTAINER_LABEL_CLIENT_OPERATIONAL1_KEY), 1);

    iot_safe_error_t ret = IOT_SAFE_SUCCESS;
    uint8_t eckey[IOT_SAFE_PUBLIC_KEY_DATA_LENGTH];
    uint16_t keylen = sizeof(eckey);
    const uint8_t * label = "operationalKey1";

    ret = iot_safe_read_public_key(channel, 
                                    NULL, 0, 
                                    label, 15, 
                                    eckey, &keylen);
    char * result = strdup(TOHEX(&eckey[6], 65));

    return result;
}

unsigned char *compute_signature(unsigned char * data, uint32_t length ){
  iot_safe_error_t ret;
  unsigned char signature[72];
  const uint8_t * label = "operationalKey1";
  uint16_t sig_len;

  ret = iot_safe_sign(channel,
                    IOT_SAFE_SIGNATURE_OPERATION_MODE_FULL_TEXT,
                    IOT_SAFE_HASH_SHA_256,
                    IOT_SAFE_SIGNATURE_ECDSA,
                    NULL, 0,
                    label, 15,
                    data, length,
                    (uint8_t *) signature,
                    sizeof(signature),
                    &sig_len);

  unsigned char * result;
  result = malloc(65);
  memcpy(result,signature,sig_len);
  return result;
}

uint16_t verify_signature(unsigned char * data, uint32_t data_len, unsigned char *signature){
  iot_safe_error_t ret = IOT_SAFE_SUCCESS;
  const uint8_t * label = "operationalKey1";

  ret = iot_safe_verify(channel,
                        IOT_SAFE_SIGNATURE_OPERATION_MODE_FULL_TEXT,
                        IOT_SAFE_HASH_SHA_256, IOT_SAFE_SIGNATURE_ECDSA,
                        NULL, 0,
                        label,15,
                        data, data_len, 
                        signature, 64);

  return ret;
}

void free_p(char * ptr){
  free(ptr);
}

int main(int argc, char const *argv[])
{ 

    // unsigned char * test = create_token("{\"claimData\": {\"blockNumber\": 999999999999}, \"iss\": \"did:ethr:0xf4a96dd3E1437D5a32A9F41b23897202F363B0aF\"}",106);
    // printf("jwt = %s\n", test);
    // free(test);
    // unsigned char * pem = pub2pem();
    // printf("%s",pem);
    // free(pem);

    uint16_t init = initialize();
    INFO("INIT : %d", init);

    //char* pubkey = read_public_key();
    //INFO("Pubkey : %s", pubkey);
    uint32_t len = strlen("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJjbGFpbURhdGEiOiB7ImJsb2NrTnVtYmVyIjogOTk5OTk5OTk5OTk5fSwgImlzcyI6ICJkaWQ6ZXRocjoweGY0YTk2ZGQzRTE0MzdENWEzMkE5RjQxYjIzODk3MjAyRjM2M0IwYUYifQ");
    unsigned char * signature = compute_signature("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJjbGFpbURhdGEiOiB7ImJsb2NrTnVtYmVyIjogOTk5OTk5OTk5OTk5fSwgImlzcyI6ICJkaWQ6ZXRocjoweGY0YTk2ZGQzRTE0MzdENWEzMkE5RjQxYjIzODk3MjAyRjM2M0IwYUYifQ", len*2);
    INFO("Signature : %s", signature);

    unsigned char sig[64];
    for (size_t i = 0; i < 64; i++)
    {
      sig[i]=signature[i];
    }
    free(signature);

    printf("%s", TOHEX(sig,64));
    uint16_t verif = verify_signature("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJjbGFpbURhdGEiOiB7ImJsb2NrTnVtYmVyIjogOTk5OTk5OTk5OTk5fSwgImlzcyI6ICJkaWQ6ZXRocjoweGY0YTk2ZGQzRTE0MzdENWEzMkE5RjQxYjIzODk3MjAyRjM2M0IwYUYifQ",len*2,sig);
    INFO("VERIF : %d", verif);
    //free_p(signature);
    //free_p(pubkey);
    
    // uint16_t close = cleanup();
    // INFO("close : %d", close);
    return 0;
}