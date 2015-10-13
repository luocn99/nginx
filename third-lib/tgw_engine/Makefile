STATIC_LIB=libtgw_engine.a
LIBRESSL_PATH=../libressl-2.3.1/openssl/
INC_FLAG=-I${LIBRESSL_PATH}/include/ -Itls_proto/
all: STATIC_LIB
	@echo "creating static lib for ${STATIC_LIB}"
	cd tls_proto/ && protoc-c --c_out=. tls_message.proto 
STATIC_LIB: tgw_engine.o tls_message.pb-c.o
	ar cr ${STATIC_LIB} $^
%.o: %.c
	gcc -c ${INC_FLAG} $<
