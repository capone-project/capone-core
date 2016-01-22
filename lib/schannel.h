#include <stdint.h>

#include <sodium/crypto_box.h>

struct schannel {
    int fd;

    uint8_t nonce[crypto_box_NONCEBYTES];
    uint8_t nonce_offset;

    uint8_t pkey[crypto_box_PUBLICKEYBYTES];
    uint8_t skey[crypto_box_SECRETKEYBYTES];
    uint8_t rkey[crypto_box_PUBLICKEYBYTES];
};

int schannel_init(struct schannel *channel, uint8_t *pkey, uint8_t *skey, uint8_t *rkey);
int schannel_close(struct schannel *channel);

int schannel_connect(struct schannel *channel, char *host, uint32_t port);
int schannel_write(struct schannel *c, uint8_t *buf, size_t len);
int schannel_receive(struct schannel *c, void *buf, size_t maxlen);
