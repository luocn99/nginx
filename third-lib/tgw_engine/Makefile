STATIC_LIB=libtgw_engine.a
LIBRESSL_PATH=../libressl-2.3.1/openssl/
INC_FLAG=-I${LIBRESSL_PATH}/include/
all: STATIC_LIB
	@echo "creating static lib for ${STATIC_LIB}"
STATIC_LIB: tgw_engine.o
	ar cr ${STATIC_LIB} $^
tgw_engine.o:
	gcc -fpic -c ${INC_FLAG} tgw_engine.c
