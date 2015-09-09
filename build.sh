#!/bin/bash
 
 #if [ -d output ]; then
 #    rm -rf output/*
 #fi
 #
 #mkdir    output
 #mkdir -p output/bin
 #mkdir -p output/conf
#
#echo "pwd is" 
#hostname -i 
#pwd
#
ROOT_PATH=`pwd`
UTIL_PATH=$ROOT_PATH/third-lib/
PCRE_PATH=$UTIL_PATH/pcre-8.36
OPENSSL_PATH=$UTIL_PATH/boringssl/openssl
NGX_PATH="./nginx-1.9.4"
cd $NGX_PATH
./configure \
    --with-http_ssl_module \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_spdy_module \
    --with-http_gzip_static_module \
    --with-debug \
    --with-pcre=$PCRE_PATH \
    #--with-openssl=/data1/lancelotluo/https/openssl/openssl-1.0.2d/myssl \
    --with-openssl=$OPENSSL_PATH \
    --with-ld-opt="-lrt"
#    --add-module=src/http/modules/thirdparty_module \
#    --add-module=src/http/modules/thirdparty_module/https_identify_ngx_module \
#    --add-module=src/http/modules/thirdparty_module/ngx_http_upstream_check_module \
#    --add-module=src/http/modules/thirdparty_module/anti-attack-module \
#    --add-module=src/http/modules/thirdparty_module/ngx_http_bfe_sslinfo_module \
#    --add-module=src/http/modules/thirdparty_module/ngx_http_bfe_sslinfo_handler_module
#
#echo "scmpf_module_version:$SCMPF_MODULE_VERSION"
#
#[[ -n $SCMPF_MODULE_VERSION ]] && sed -i 's/^#define NGINX_VERSION.*/#define NGINX_VERSION      '\"${SCMPF_MODULE_VERSION}\"'/g' src/core/nginx.h

make -f objs/Makefile
#&& cp objs/nginx output/bin/ \
#&& mkdir -p output/redis_server/ && cp -r utils/redis/redis_server/* output/redis_server/ \
#&& mkdir -p output/redis_proxy/ && cp -r utils/redis/redis_proxy/* output/redis_proxy/ \
#&& cp -r ngx_online_conf/* output/conf/
