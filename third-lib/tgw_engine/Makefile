STATIC_LIB=libtgw_engine.a
LIBRESSL_PATH=../libressl-2.3.1/openssl/
INC_FLAG=-I${LIBRESSL_PATH}/include/ -Itls_proto/  -I../common/
COMMON_OBJ=../common/common.o
OBJS= tgw_engine.o tgw_pbmsg.o ${COMMON_OBJ} ./tls_proto/tls_message.pb-c.o
all: ${STATIC_LIB}
.PHONY: all
	@echo "creating static lib for ${STATIC_LIB}"
	cd tls_proto/ && protoc-c --c_out=. tls_message.proto 
${STATIC_LIB}: ${OBJS}
	ar cr ${STATIC_LIB} ${OBJS}
	
${OBJS}: %.o:%.c
	gcc -c ${INC_FLAG} $< -o $@

remote_server: remote_server.o
	@echo "hello"
	gcc -g -Wall ${INC_FLAG} -L${LIBRESSL_PATH} -o $@ $< ./tls_proto/tls_message.pb-c.o ../common/common.o tgw_pbmsg.o -lcrypto  -lprotobuf-c
remote_server.o:%.o:%.c
	gcc -g -Wall ${INC_FLAG} -L${LIBRESSL_PATH} -c -o $@ $< 

clean:
	rm -rf ${STATIC_LIB} ${OBJS}
