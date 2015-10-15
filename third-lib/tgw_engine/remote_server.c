#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "common.h"
#include "tls_message.pb-c.h"
#include "tgw_pbmsg.h"



int main()
{
    RSA *k  = NULL;

    int sock_fd = 0, conn_fd = 0, n = 0;
    struct sockaddr_in serv_addr;
    unsigned char recv_buf[2048] = {0};

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
         printf("fail to create socket\n");
         return -1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(10001);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(sock_fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
    listen(sock_fd, 100000);
    int sum = 0;
    while(1) {
        conn_fd = accept(sock_fd, (struct sockaddr*)NULL, NULL);

        n = read(conn_fd, recv_buf, 2048);
        sum += n;
        if  (sum >= 1)
            break;
    }

    printf("suc to read:%d bytes\n", sum);
    RsaRemoteReq *req = NULL;
    if ((req = rsa_remote_req__unpack(NULL, sum, recv_buf)) == NULL) {
        printf("fail to unpack rsa_dec_req\n");
    }
    printf("req id:%d req version:%d  private_key_len:%d\n", req->id, req->version, req->private_key_len);

    printf("encrypt len:%lu txt:\n", req->msg.len);
    print_hex(req->msg.data, req->msg.len);
    printf("private key len:%lu\n", req->private_key.len);
    print_hex(req->private_key.data, req->private_key_len);

    k = d2i_RSAPrivateKey(NULL, (const unsigned char **)&req->private_key.data, req->private_key_len);
    if (k == NULL) {
         printf("fail to d2i rsa private key\n");
         return -1;
    }

    uint8_t  *crypt_txt = req->msg.data;
    int crypt_len = req->msg.len;
    int padding   = req->padding;
    unsigned char decrypt[2048] = {0};
    int decrypt_len = RSA_private_decrypt(crypt_len ,crypt_txt, decrypt, k, padding);
    printf("suc to decrypt len:%d  txt:%s\n", decrypt_len,  decrypt);

    printf("rsa private key len:%lu\n", req->private_key.len);
    RsaRemoteRsp rsp = RSA_REMOTE_RSP__INIT;
    tgw_marshal_pb_rsarsp(&rsp, decrypt, decrypt_len, req->id);

    int pack_size = rsa_remote_rsp__get_packed_size(&rsp);
    printf("remote_rsp pack_size:%d, file:%s line:%d\n", pack_size, __FILE__, __LINE__);
    void *pb_buf = malloc(pack_size);
    rsa_remote_rsp__pack((const RsaRemoteRsp *)&rsp, pb_buf);
    int w_len = write(conn_fd, pb_buf, pack_size);
    printf("suc to send %d bytes\n", w_len);

    return 0;
}
