#ifndef __TGW_PBMSG__H__
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include "tls_proto/tls_message.pb-c.h"
#include "openssl/crypto.h"
#include "openssl/engine.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"

int tgw_get_rsareq_fd();
int tgw_read_pb(int sock_fd, void *buf, int len);
int tgw_write_pb_rsareq(int sock_fd, RsaRemoteReq *req);
int tgw_marshal_pb_rsareq(RsaRemoteReq *req, RSA *rsa, const uint8_t *from, int flen, int padding, int type);
int tgw_marshal_pb_rsarsp(RsaRemoteRsp *rsp, uint8_t *from, int flen, int id);

#endif
