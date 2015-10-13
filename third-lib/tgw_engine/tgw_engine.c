#include <stdio.h>
#include <string.h>
#include "openssl/crypto.h"
#include "openssl/buffer.h"
#include "openssl/engine.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"

#include "tgw_engine.h"
/*
static int e_gmp_init(ENGINE *e);
static int e_gmp_finish(ENGINE *e);
static int e_gmp_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void));
*/

/* Constants used when creating the ENGINE */
static const char *engine_e_tgw_id = "tgw";
static const char *engine_e_tgw_name = "TGW engine support";
static size_t size(const RSA *rsa);
static int tgw_rsa_private_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);
static int tgw_rsa_private_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);
static int tgw_rsa_mod_exp(BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx);
static int tgw_rsa_init(RSA *rsa);
static int tgw_rsa_finish(RSA *rsa);

const struct rsa_meth_st tgw_remote_rsa_meth = {
    .name = "tgw_pkcs#1", // name
    .rsa_pub_enc = NULL, // rsa_pub_enc
    .rsa_pub_dec = NULL, // rsa_pub_dec

    .rsa_priv_enc = tgw_rsa_private_encrypt, // rsa_priv_enc
    .rsa_priv_dec = tgw_rsa_private_decrypt, // rsa_priv_dec

    .rsa_mod_exp = tgw_rsa_mod_exp, // rsa_mod_exp
    .bn_mod_exp  = BN_mod_exp_mont, // bn_mod_exp

    NULL, // init
    NULL, // finish

    RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE, // flags
    NULL, // app_data
    NULL, // rsa sign
    NULL, // rsa  verify

    NULL, // rsa keygen
};

/*
 * This internal function is used by ENGINE_gmp() and possibly by the
 * "dynamic" ENGINE support too
 */
static int bind_helper(ENGINE *e)
{
    if (!ENGINE_set_id(e, engine_e_tgw_id) ||
        !ENGINE_set_name(e, engine_e_tgw_name) )
        return 0;
    /*
        !ENGINE_set_destroy_function(e, e_gmp_destroy) ||
        !ENGINE_set_init_function(e, e_gmp_init) ||
        !ENGINE_set_finish_function(e, e_gmp_finish) ||
        !ENGINE_set_ctrl_function(e, e_gmp_ctrl) ||
        !ENGINE_set_cmd_defns(e, e_gmp_cmd_defns))
    */
    ENGINE_set_RSA(e, &tgw_remote_rsa_meth);
    /*
#  ifndef OPENSSL_NO_RSA
    meth1 = RSA_PKCS1_SSLeay();
    e_gmp_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
    e_gmp_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
    e_gmp_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
    e_gmp_rsa.rsa_priv_dec = meth1->rsa_priv_dec;
    e_gmp_rsa.bn_mod_exp = meth1->bn_mod_exp;
#  endif

    */
    return 1;
}

static ENGINE *engine_tgw(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_helper(ret)) {
        printf("tgw engine, fail to bind_helper file:%s line:%d\n", __FILE__, __LINE__);
        ENGINE_free(ret);
        return NULL;
    }
    printf("tgw engine, hi, file:%s line:%d\n", __FILE__, __LINE__);
    return ret;
}

void ENGINE_load_tgw(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_tgw();
    if (!toadd)
        return;
    printf("tgw engine, hi, file:%s line:%d\n", __FILE__, __LINE__);
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


/*
 * This stuff is needed if this ENGINE is being compiled into a
 * self-contained shared-library.
 */
# ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_CHECK_FN()
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_e_tgw_id) != 0))
        return 0;
    if (!bind_helper(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#  else
    /*
OPENSSL_EXPORT
    int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns)
{
    return 0;
}
*/
#  endif

#define OPENSSL_RSA_MAX_MODULUS_BITS 16384
#define OPENSSL_RSA_SMALL_MODULUS_BITS 3072
#define OPENSSL_RSA_MAX_PUBEXP_BITS \
  64 /* exponent limit enforced for "large" modulus only */


static int finish(RSA *rsa) {
  BN_MONT_CTX_free(rsa->_method_mod_n);
  BN_MONT_CTX_free(rsa->_method_mod_p);
  BN_MONT_CTX_free(rsa->_method_mod_q);

  return 1;
}

static size_t size(const RSA *rsa) {
  return BN_num_bytes(rsa->n);
}
/*
static int send_pb(uint8_t *buf, int len) {
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

    n = write(sock_fd, buf, len);
    printf("suc to send:%d bytes\n", n);

    return n;
}
*/

    /*
    int r = -1;
    uint8_t *buf = NULL;
    int ret = 0;

    printf("tgw decrypt, file:%s line:%d \n", __FILE__, __LINE__);

    if (max_out < rsa_size) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    RsaDecReq req = RSA_DEC_REQ__INIT;
    req.has_id = 1;
    req.id        = 18;
    req.version   = 2;
    req.has_version = 1;
    req.max_out   = 13;
    req.has_max_out = 1;
    req.out_len   = *out_len;
    req.has_out_len = 1;
    req.padding   = 11;
    req.has_padding = 1;
    unsigned char *key_buf = NULL;
    printf("hi, file:%s line:%d\n", __FILE__, __LINE__);
    int key_len  =  i2d_RSAPrivateKey(rsa, (uint8_t **) &key_buf);
    printf("hi, file:%s line:%d\n", __FILE__, __LINE__);
    req.private_key.data = (uint8_t *)malloc(key_len);
    req.private_key.len  = key_len;
    req.encrypt_txt.data = (uint8_t *)malloc(in_len);
    req.encrypt_txt.len  = in_len;
    memcpy(req.private_key.data, key_buf, key_len);
    memcpy(req.encrypt_txt.data, in, in_len);
    printf("memcpy to req.private_key, key_len:%d\n", key_len);
    printf("i2d_rsaprivatekey len:%d max_out:%d padding:%d id:%d\n", key_len, req.max_out, req.padding, req.id);
    printf("key buf:\n");
    req.private_key_len = key_len;
    req.has_private_key_len = 1;
    print_hex(key_buf, key_len);
    printf("private key\n");
    print_hex(req.private_key.data, key_len);
    req.has_private_key = 1;
    req.has_encrypt_txt = 1;
    printf("hi, private key len:%d file:%s line:%d\n", req.private_key_len,  __FILE__, __LINE__);

    printf("encrypt txt:\n");
    print_hex(req.encrypt_txt.data, in_len);

    int pack_size = rsa_dec_req__get_packed_size(&req);
    printf("packed size:%d\n", pack_size);
    void *pb_buf = malloc(pack_size);
    rsa_dec_req__pack(&req, pb_buf);

    send_pb(pb_buf, pack_size);

    sleep(1);
    printf("hi file:%s line:%d\n", __FILE__, __LINE__);
    RsaDecReq *re = rsa_dec_req__unpack(NULL, pack_size, pb_buf);
    printf("hi file:%s line:%d\n", __FILE__, __LINE__);
    if (re->private_key.data == NULL) {
        printf("fail to get private data\n");
        return -1;
    }
    print_hex(re->private_key.data, key_len);
    printf("hi file:%s line:%d\n", __FILE__, __LINE__);

    if (padding == RSA_NO_PADDING) {
        buf = out;
    } else {
        // Allocate a temporary buffer to hold the padded plaintext.
        buf = OPENSSL_malloc(rsa_size);
        if (buf == NULL) {
            OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if (in_len != rsa_size) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN);
        goto err;
    }

    printf("my decrypt, file:%s line:%d \n", __FILE__, __LINE__);
    if (!RSA_private_transform(rsa, buf, in, rsa_size)) {
        goto err;
    }
    printf("my decrypt, file:%s line:%d \n", __FILE__, __LINE__);

    switch (padding) {
        case RSA_PKCS1_PADDING:
            r = RSA_padding_check_PKCS1_type_2(out, rsa_size, buf, rsa_size);
            break;
        case RSA_PKCS1_OAEP_PADDING:
            // Use the default parameters: SHA-1 for both hashes and no label.
            r = RSA_padding_check_PKCS1_OAEP_mgf1(out, rsa_size, buf, rsa_size,
                    NULL, 0, NULL, NULL);
            break;
        case RSA_NO_PADDING:
            r = rsa_size;
            break;
        default:
            OPENSSL_PUT_ERROR(RSA, RSA_R_UNKNOWN_PADDING_TYPE);
            goto err;
    }
    printf("my decrypt, file:%s line:%d \n", __FILE__, __LINE__);

    if (r < 0) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_PADDING_CHECK_FAILED);
    } else {
        *out_len = r;
        ret = 1;
    }

err:
    if (padding != RSA_NO_PADDING && buf != NULL) {
        OPENSSL_cleanse(buf, rsa_size);
        OPENSSL_free(buf);
    }
    return ret;
*/

//follow ing code copy from libressl
//
static BN_BLINDING *
rsa_get_blinding(RSA *rsa, int *local, BN_CTX *ctx)
{
	BN_BLINDING *ret;
	int got_write_lock = 0;
	CRYPTO_THREADID cur;

	CRYPTO_r_lock(CRYPTO_LOCK_RSA);

	if (rsa->blinding == NULL) {
		CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
		CRYPTO_w_lock(CRYPTO_LOCK_RSA);
		got_write_lock = 1;

		if (rsa->blinding == NULL)
			rsa->blinding = RSA_setup_blinding(rsa, ctx);
	}

	ret = rsa->blinding;
	if (ret == NULL)
		goto err;

	CRYPTO_THREADID_current(&cur);
	if (!CRYPTO_THREADID_cmp(&cur, BN_BLINDING_thread_id(ret))) {
		/* rsa->blinding is ours! */
		*local = 1;
	} else {
		/* resort to rsa->mt_blinding instead */
		/*
		 * Instruct rsa_blinding_convert(), rsa_blinding_invert()
		 * that the BN_BLINDING is shared, meaning that accesses
		 * require locks, and that the blinding factor must be
		 * stored outside the BN_BLINDING
		 */
		*local = 0;

		if (rsa->mt_blinding == NULL) {
			if (!got_write_lock) {
				CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
				CRYPTO_w_lock(CRYPTO_LOCK_RSA);
				got_write_lock = 1;
			}

			if (rsa->mt_blinding == NULL)
				rsa->mt_blinding = RSA_setup_blinding(rsa, ctx);
		}
		ret = rsa->mt_blinding;
	}

err:
	if (got_write_lock)
		CRYPTO_w_unlock(CRYPTO_LOCK_RSA);
	else
		CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
	return ret;
}
static int
rsa_blinding_convert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind, BN_CTX *ctx)
{
	if (unblind == NULL)
		/*
		 * Local blinding: store the unblinding factor
		 * in BN_BLINDING.
		 */
		return BN_BLINDING_convert_ex(f, NULL, b, ctx);
	else {
		/*
		 * Shared blinding: store the unblinding factor
		 * outside BN_BLINDING.
		 */
		int ret;
		CRYPTO_w_lock(CRYPTO_LOCK_RSA_BLINDING);
		ret = BN_BLINDING_convert_ex(f, unblind, b, ctx);
		CRYPTO_w_unlock(CRYPTO_LOCK_RSA_BLINDING);
		return ret;
	}
}

static int
rsa_blinding_invert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind, BN_CTX *ctx)
{
	/*
	 * For local blinding, unblind is set to NULL, and BN_BLINDING_invert_ex
	 * will use the unblinding factor stored in BN_BLINDING.
	 * If BN_BLINDING is shared between threads, unblind must be non-null:
	 * BN_BLINDING_invert_ex will then use the local unblinding factor,
	 * and will only read the modulus from BN_BLINDING.
	 * In both cases it's safe to access the blinding without a lock.
	 */
	return BN_BLINDING_invert_ex(f, unblind, b, ctx);
}
/* signing */
static int
tgw_rsa_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	BIGNUM *f, *ret, *res;
	int i, j, k, num = 0, r = -1;
	unsigned char *buf = NULL;
	BN_CTX *ctx = NULL;
	int local_blinding = 0;
	/*
	 * Used only if the blinding structure is shared. A non-NULL unblind
	 * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
	 * the unblinding factor outside the blinding structure.
	 */
	BIGNUM *unblind = NULL;
	BN_BLINDING *blinding = NULL;

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = malloc(num);
	if (f == NULL || ret == NULL || buf == NULL) {
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	switch (padding) {
	case RSA_PKCS1_PADDING:
		i = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
		break;
	case RSA_X931_PADDING:
		i = RSA_padding_add_X931(buf, num, from, flen);
		break;
	case RSA_NO_PADDING:
		i = RSA_padding_add_none(buf, num, from, flen);
		break;
	case RSA_SSLV23_PADDING:
	default:
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,
		    RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (i <= 0)
		goto err;

	if (BN_bin2bn(buf, num, f) == NULL)
		goto err;

	if (BN_ucmp(f, rsa->n) >= 0) {
		/* usually the padding functions would catch this */
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,
		    RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
	}

	if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
		blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
		if (blinding == NULL) {
			RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}

	if (blinding != NULL) {
		if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
			RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}
		if (!rsa_blinding_convert(blinding, f, unblind, ctx))
			goto err;
	}

	if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
	    (rsa->p != NULL && rsa->q != NULL && rsa->dmp1 != NULL &&
	    rsa->dmq1 != NULL && rsa->iqmp != NULL)) {
		if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
			goto err;
	} else {
		BIGNUM local_d;
		BIGNUM *d = NULL;

		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
			BN_init(&local_d);
			d = &local_d;
			BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
		} else
			d = rsa->d;

		if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
			    CRYPTO_LOCK_RSA, rsa->n, ctx))
				goto err;

		if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
		    rsa->_method_mod_n))
			goto err;
	}

	if (blinding)
		if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
			goto err;

	if (padding == RSA_X931_PADDING) {
		BN_sub(f, rsa->n, ret);
		if (BN_cmp(ret, f) > 0)
			res = f;
		else
			res = ret;
	} else
		res = ret;

	/* put in leading 0 bytes if the number is less than the
	 * length of the modulus */
	j = BN_num_bytes(res);
	i = BN_bn2bin(res, &(to[num - j]));
	for (k = 0; k < num - i; k++)
		to[k] = 0;

	r = num;
err:
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (buf != NULL) {
		explicit_bzero(buf, num);
		free(buf);
	}
	return r;
}

static int tgw_rsa_private_decrypt(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
{
	BIGNUM *f, *ret;
	int j, num = 0, r = -1;
	unsigned char *p;
	unsigned char *buf = NULL;
	BN_CTX *ctx = NULL;
	int local_blinding = 0;
	/*
	 * Used only if the blinding structure is shared. A non-NULL unblind
	 * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
	 * the unblinding factor outside the blinding structure.
	 */
	BIGNUM *unblind = NULL;
	BN_BLINDING *blinding = NULL;

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = malloc(num);
	if (!f || !ret || !buf) {
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* This check was for equality but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num) {
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
		    RSA_R_DATA_GREATER_THAN_MOD_LEN);
		goto err;
	}

	/* make data into a big number */
	if (BN_bin2bn(from, (int)flen, f) == NULL)
		goto err;

	if (BN_ucmp(f, rsa->n) >= 0) {
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
		    RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
	}

	if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
		blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
		if (blinding == NULL) {
			RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}

	if (blinding != NULL) {
		if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
			RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}
		if (!rsa_blinding_convert(blinding, f, unblind, ctx))
			goto err;
	}

	/* do the decrypt */
	if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
	    (rsa->p != NULL && rsa->q != NULL && rsa->dmp1 != NULL &&
	    rsa->dmq1 != NULL && rsa->iqmp != NULL)) {
		if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
			goto err;
	} else {
		BIGNUM local_d;
		BIGNUM *d = NULL;

		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
			d = &local_d;
			BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
		} else
			d = rsa->d;

		if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
			    CRYPTO_LOCK_RSA, rsa->n, ctx))
				goto err;
		if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
		    rsa->_method_mod_n))
			goto err;
	}

	if (blinding)
		if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
			goto err;

	p = buf;
	j = BN_bn2bin(ret, p); /* j is only used with no-padding mode */

	switch (padding) {
	case RSA_PKCS1_PADDING:
		r = RSA_padding_check_PKCS1_type_2(to, num, buf, j, num);
		break;
#ifndef OPENSSL_NO_SHA
	case RSA_PKCS1_OAEP_PADDING:
		r = RSA_padding_check_PKCS1_OAEP(to, num, buf, j, num, NULL, 0);
		break;
#endif
	case RSA_SSLV23_PADDING:
		r = RSA_padding_check_SSLv23(to, num, buf, j, num);
		break;
	case RSA_NO_PADDING:
		r = RSA_padding_check_none(to, num, buf, j, num);
		break;
	default:
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
		    RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (r < 0)
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
		    RSA_R_PADDING_CHECK_FAILED);

err:
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (buf != NULL) {
		explicit_bzero(buf, num);
		free(buf);
	}
	return r;
}

static int
tgw_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
	BIGNUM *r1, *m1, *vrfy;
	BIGNUM local_dmp1, local_dmq1, local_c, local_r1;
	BIGNUM *dmp1, *dmq1, *c, *pr1;
	int ret = 0;

	BN_CTX_start(ctx);
	r1 = BN_CTX_get(ctx);
	m1 = BN_CTX_get(ctx);
	vrfy = BN_CTX_get(ctx);
	if (r1 == NULL || m1 == NULL || vrfy == NULL) {
		RSAerr(RSA_F_RSA_EAY_MOD_EXP, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	{
		BIGNUM local_p, local_q;
		BIGNUM *p = NULL, *q = NULL;

		/*
		 * Make sure BN_mod_inverse in Montgomery intialization uses the
		 * BN_FLG_CONSTTIME flag (unless RSA_FLAG_NO_CONSTTIME is set)
		 */
		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
			BN_init(&local_p);
			p = &local_p;
			BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);

			BN_init(&local_q);
			q = &local_q;
			BN_with_flags(q, rsa->q, BN_FLG_CONSTTIME);
		} else {
			p = rsa->p;
			q = rsa->q;
		}

		if (rsa->flags & RSA_FLAG_CACHE_PRIVATE) {
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_p,
			    CRYPTO_LOCK_RSA, p, ctx))
				goto err;
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_q,
			    CRYPTO_LOCK_RSA, q, ctx))
				goto err;
		}
	}

	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
		    CRYPTO_LOCK_RSA, rsa->n, ctx))
			goto err;

	/* compute I mod q */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		c = &local_c;
		BN_with_flags(c, I, BN_FLG_CONSTTIME);
		if (!BN_mod(r1, c, rsa->q, ctx))
			goto err;
	} else {
		if (!BN_mod(r1, I, rsa->q, ctx))
			goto err;
	}

	/* compute r1^dmq1 mod q */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		dmq1 = &local_dmq1;
		BN_with_flags(dmq1, rsa->dmq1, BN_FLG_CONSTTIME);
	} else
		dmq1 = rsa->dmq1;
	if (!rsa->meth->bn_mod_exp(m1, r1, dmq1, rsa->q, ctx,
	    rsa->_method_mod_q))
		goto err;

	/* compute I mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		c = &local_c;
		BN_with_flags(c, I, BN_FLG_CONSTTIME);
		if (!BN_mod(r1, c, rsa->p, ctx))
			goto err;
	} else {
		if (!BN_mod(r1, I, rsa->p, ctx))
			goto err;
	}

	/* compute r1^dmp1 mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		dmp1 = &local_dmp1;
		BN_with_flags(dmp1, rsa->dmp1, BN_FLG_CONSTTIME);
	} else
		dmp1 = rsa->dmp1;
	if (!rsa->meth->bn_mod_exp(r0, r1, dmp1, rsa->p, ctx,
	    rsa->_method_mod_p))
		goto err;

	if (!BN_sub(r0, r0, m1))
		goto err;
	/*
	 * This will help stop the size of r0 increasing, which does
	 * affect the multiply if it optimised for a power of 2 size
	 */
	if (BN_is_negative(r0))
		if (!BN_add(r0, r0, rsa->p))
			goto err;

	if (!BN_mul(r1, r0, rsa->iqmp, ctx))
		goto err;

	/* Turn BN_FLG_CONSTTIME flag on before division operation */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		pr1 = &local_r1;
		BN_with_flags(pr1, r1, BN_FLG_CONSTTIME);
	} else
		pr1 = r1;
	if (!BN_mod(r0, pr1, rsa->p, ctx))
		goto err;

	/*
	 * If p < q it is occasionally possible for the correction of
	 * adding 'p' if r0 is negative above to leave the result still
	 * negative. This can break the private key operations: the following
	 * second correction should *always* correct this rare occurrence.
	 * This will *never* happen with OpenSSL generated keys because
	 * they ensure p > q [steve]
	 */
	if (BN_is_negative(r0))
		if (!BN_add(r0, r0, rsa->p))
			goto err;
	if (!BN_mul(r1, r0, rsa->q, ctx))
		goto err;
	if (!BN_add(r0, r1, m1))
		goto err;

	if (rsa->e && rsa->n) {
		if (!rsa->meth->bn_mod_exp(vrfy, r0, rsa->e, rsa->n, ctx,
		    rsa->_method_mod_n))
			goto err;
		/*
		 * If 'I' was greater than (or equal to) rsa->n, the operation
		 * will be equivalent to using 'I mod n'. However, the result of
		 * the verify will *always* be less than 'n' so we don't check
		 * for absolute equality, just congruency.
		 */
		if (!BN_sub(vrfy, vrfy, I))
			goto err;
		if (!BN_mod(vrfy, vrfy, rsa->n, ctx))
			goto err;
		if (BN_is_negative(vrfy))
			if (!BN_add(vrfy, vrfy, rsa->n))
				goto err;
		if (!BN_is_zero(vrfy)) {
			/*
			 * 'I' and 'vrfy' aren't congruent mod n. Don't leak
			 * miscalculated CRT output, just do a raw (slower)
			 * mod_exp and return that instead.
			 */

			BIGNUM local_d;
			BIGNUM *d = NULL;

			if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
				d = &local_d;
				BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
			} else
				d = rsa->d;
			if (!rsa->meth->bn_mod_exp(r0, I, d, rsa->n, ctx,
			    rsa->_method_mod_n))
				goto err;
		}
	}
	ret = 1;
err:
	BN_CTX_end(ctx);
	return ret;
}
