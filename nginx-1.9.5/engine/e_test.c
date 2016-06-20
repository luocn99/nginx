#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/ui.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#include <openssl/bn.h>

#include "e_test.h"

#ifndef OPENSSL_NO_HW

/* the header file of vender */
//#include "hwdevice.h"

/* Constants used when creating the ENGINE */
static const char *engine_hwdev_id = "hwdev";
static const char *engine_hwdev_name = "hardware of device";
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
/* Compatibility hack, the dynamic library uses this form in the path */
static const char *engine_hwdev_id_alt = "hwdev";
#endif

#ifndef OPENSSL_NO_RSA
static int test_rsa_pub_enc(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
{
    fprintf(stderr, "%s|%d --> arrive at test_rsa_pub_enc\n", __FILE__, __LINE__);
    return 1;
}

static int test_rsa_pub_dec(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
{
    fprintf(stderr, "%s|%d --> arrive at test_rsa_pub_dec\n", __FILE__, __LINE__);
    return 1;
}

static int test_rsa_priv_enc(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
{
    fprintf(stderr, "%s|%d --> arrive at test_rsa_priv_enc\n", __FILE__, __LINE__);
    return 1;
}

static int test_rsa_priv_dec(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
{
    fprintf(stderr, "%s|%d --> arrive at test_rsa_priv_dec\n", __FILE__, __LINE__);
    return 1;
}

static int test_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I,
        RSA *rsa, BN_CTX *ctx)
{
    fprintf(stderr, "%s|%d --> arrive at test_rsa_mod_exp\n", __FILE__, __LINE__);
    return 1;
}

static test_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
        const BIGNUM *m, BN_CTX *ctx,
        BN_MONT_CTX *m_ctx)
{
    fprintf(stderr, "%s|%d --> arrive at test_bn_mod_exp\n", __FILE__, __LINE__);
    return 1;
}

static int test_init(RSA *rsa)
{
    fprintf(stderr, "%s|%d --> arrive at test_init\n", __FILE__, __LINE__);
    return 1;
}

static int test_finish(RSA *rsa)
{
    fprintf(stderr, "%s|%d --> arrive at test_init\n", __FILE__, __LINE__);
    return 1;
}

static RSA_METHOD hwdev_rsa =
{
    "TEST RSA method",
    test_rsa_pub_enc,
    test_rsa_pub_dec,
    test_rsa_priv_enc,
    test_rsa_priv_dec,
    test_rsa_mod_exp,
    test_bn_mod_exp,
    test_init,
    test_finish,
    0,
    NULL, /* we my set some data of the hwdev here */
    NULL,
    NULL,
    NULL
};
#endif

static int hwdev_destroy(ENGINE *e)
{
    fprintf(stderr, "arrive at hwdev_destroy\n");
    return 1;
}

static int hwdev_init(ENGINE *e)
{
    fprintf(stderr, "arrive at hwdev_init\n");
    return 1;
}

static int hwdev_finish(ENGINE *e)
{
    fprintf(stderr, "arrive at hwdev_finish\n");
    return 1;
}

/* The definitions for control commands specific to this engine */
#define HWDEV_CMD_INIT  (ENGINE_CMD_BASE)
#define HWDEV_CMD_EXIT  (ENGINE_CMD_BASE + 1)
#define HWDEV_CMD_TEST  (ENGINE_CMD_BASE + 2)
static const ENGINE_CMD_DEFN hwdev_cmd_defns[] = {
    {HWDEV_CMD_INIT,
        "INIT",
        "init the hardware device before using",
        ENGINE_CMD_FLAG_STRING}, /* may be the password */
    {HWDEV_CMD_EXIT,
        "EXIT",
        "exit the hardware device after using",
        ENGINE_CMD_FLAG_NO_INPUT},
    {HWDEV_CMD_TEST,
        "TEST",
        "run the test case of the hardware device",
        ENGINE_CMD_FLAG_NUMERIC}, /* may be the number of test case */
    {0, NULL, NULL, 0}
    };

/* This internal function is used by ENGINE_chil() and possibly by the
 * "dynamic" ENGINE support too */
static int hwdev_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    int to_return = 1;

    switch(cmd) {
    case HWDEV_CMD_INIT:
        fprintf(stderr, "arrive at HWDEV_CMD_INIT, password: %s\n",
                (const char *)p);
        break;
    case HWDEV_CMD_EXIT:
        fprintf(stderr, "arrive at HWDEV_CMD_EXIT, no parameters\n");
        break;
    case HWDEV_CMD_TEST:
        fprintf(stderr, "arrive at HWDEV_CMD_TEST, case id: %ld\n",
                i);
        break;
    /* The command isn't understood by this engine */
    default:
        to_return = 0;
        break;
    }

    return to_return;
}

static EVP_PKEY *hwdev_load_privkey(ENGINE *eng, const char *key_id,
    UI_METHOD *ui_method, void *callback_data)
{
    fprintf(stderr, "arrive at hwdev_load_privkey\n");
    EVP_PKEY *res = NULL;

    return res;
}

static EVP_PKEY *hwdev_load_pubkey(ENGINE *eng, const char *key_id,
    UI_METHOD *ui_method, void *callback_data)
{
    fprintf(stderr, "arrive at hwdev_load_pubkey\n");
    EVP_PKEY *res = NULL;

    return res;
}

static int bind_helper(ENGINE *e)
{
    fprintf(stderr, "arrive at bind_helper\n");
#ifndef OPENSSL_NO_RSA
    const RSA_METHOD *meth1;
#endif

    if(!ENGINE_set_id(e, engine_hwdev_id) ||
            !ENGINE_set_name(e, engine_hwdev_name) ||
#ifndef OPENSSL_NO_RSA
            !ENGINE_set_RSA(e, &hwdev_rsa) ||
#endif
            !ENGINE_set_destroy_function(e, hwdev_destroy) ||
            !ENGINE_set_init_function(e, hwdev_init) ||
            !ENGINE_set_finish_function(e, hwdev_finish) ||
            !ENGINE_set_ctrl_function(e, hwdev_ctrl) ||
            !ENGINE_set_load_privkey_function(e, hwdev_load_privkey) ||
            !ENGINE_set_load_pubkey_function(e, hwdev_load_pubkey) ||
            !ENGINE_set_cmd_defns(e, hwdev_cmd_defns))
        return 0;

#ifndef OPENSSL_NO_RSA
    meth1 = RSA_PKCS1_SSLeay();
    hwdev_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
    hwdev_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
    hwdev_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
    hwdev_rsa.rsa_priv_dec = meth1->rsa_priv_dec;
#endif

    return 1;
}

//#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_hwdev(void)
{
    fprintf(stderr, "arrive at engine_test\n");
    ENGINE *ret = ENGINE_new();
    if(!ret) {
        return NULL;
    }

    if(!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }

    return ret;
}

void ENGINE_load_test(void)
{
    fprintf(stderr, "arrive at ENGINE_load_test\n");
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_hwdev();
    if(!toadd) return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
//#endif


/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_fn(ENGINE *e, const char *id)
{
    fprintf(stderr, "arrive at bind_fn\n");
    if(id && (strcmp(id, engine_hwdev_id) != 0) &&
            (strcmp(id, engine_hwdev_id_alt) != 0))
        return 0;
    if(!bind_helper(e))
        return 0;
    return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* OPENSSL_NO_DYNAMIC_ENGINE */

#endif /* !OPENSSL_NO_HW */


e_test.h：

#ifndef __E_TEST_H__
#define __E_TEST_H__

extern void ENGINE_load_test(void);

#endif
