#include "tgw_pbmsg.h"
#include "openssl/crypto.h"
#include "openssl/engine.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"

int tgw_get_rsareq_fd()
{
    int sock_fd = 0, n = 0;
    struct sockaddr_in serv_addr;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
         printf("fail to create socket\n");
         return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(10001);
    if ((inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)) < 0) {
        printf("fail to inet_pton\n");
        return -1;
    }

    if (connect(sock_fd, (const struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
         printf("fail to connect \n");
         return -1;
    }

    return sock_fd;
}

int tgw_read_pb(int sock_fd, void *r_buf, int r_len)
{
    if (sock_fd < 0 || r_buf == NULL) {
        return -1;
    }

    int len = read(sock_fd, r_buf, r_len);
    printf("read %d bytes\n", len);

    return len;
}

int tgw_write_pb_rsareq(int sock_fd, RsaRemoteReq *req)
{
    printf("file:%s line:%d id:%d padding:%d\n", __FILE__, __LINE__, req->id, req->padding);
    int pack_size = rsa_remote_req__get_packed_size(req);
    printf("packed size:%d\n", pack_size);
    void *pb_buf = malloc(pack_size);
    if (pb_buf == NULL) {
         printf("fail to malloc for pb_buf\n");
         return -1;
    }
    printf("file:%s line:%d\n", __FILE__, __LINE__);

    rsa_remote_req__pack(req, pb_buf);
    printf("file:%s line:%d\n", __FILE__, __LINE__);
    int ret = write(sock_fd, pb_buf, pack_size);
    printf("file:%s line:%d\n", __FILE__, __LINE__);
    if (ret != pack_size) {
        printf("send %d bytes\n", pack_size);
    }

    printf("suc to send %d bytes, file:%s line:%d\n", pack_size, __FILE__, __LINE__);

    return ret;
}

int tgw_marshal_pb_rsareq(RsaRemoteReq *req, RSA *rsa, const uint8_t *from, int flen, int padding, int type)
{
    req->id          = 18;
    req->has_id      = 1;
    req->version     = 2;
    req->has_version = 1;
    req->from_len     = flen;
    req->has_from_len = 1;
    req->padding      = padding;
    req->has_padding  = 1;
    unsigned char *key_buf = NULL;
    printf("hi, file:%s line:%d\n", __FILE__, __LINE__);
    int key_len  =  i2d_RSAPrivateKey(rsa, (uint8_t **) &key_buf);
    printf("hi, file:%s line:%d\n", __FILE__, __LINE__);
    req->private_key.data = (uint8_t *) malloc(key_len);
    if (req->private_key.data == NULL) {
        printf("fail to malloc for private key\n");
        return -1;
    }
    req->private_key.len  = key_len;
    req->msg.data = (uint8_t *)malloc(flen);
    if (req->msg.data == NULL) {
        printf("fail to malloc for msg\n");
        return -1;
    }
    req->msg.len  = flen;
    req->has_msg = 1;
    memcpy(req->private_key.data, key_buf, key_len);
    memcpy(req->msg.data, from, flen);
    printf("memcpy to req->private_key, key_len:%d\n", key_len);
    printf("i2d_rsaprivatekey len:%d  padding:%d id:%d\n", key_len, req->padding, req->id);
    printf("key buf:\n");
    req->private_key_len = key_len;
    req->has_private_key_len = 1;
    print_hex(key_buf, key_len);
    printf("private key\n");
    print_hex(req->private_key.data, key_len);
    req->has_private_key = 1;

    printf("hi, private key len:%d file:%s line:%d\n", req->private_key_len,  __FILE__, __LINE__);
    printf("encrypt txt:\n");
    print_hex(req->msg.data, flen);

    return 0;
}

int tgw_marshal_pb_rsarsp(RsaRemoteRsp *rsp, uint8_t *from, int flen, int id)
{
     rsp->id = id;
     rsp->has_id = 1;
     rsp->msg.data = malloc(flen);
     if (rsp->msg.data == NULL) {
          printf("fail to marshal pb rsarsp\n");
          return -1;
     }
    rsp->has_msg = 1;
     memcpy(rsp->msg.data, from, flen);
     printf("suc to copy %d data to msg, file:%s , line:%d\n", flen, __FILE__, __LINE__);
    rsp->msg.len = flen;

     return flen;
}
