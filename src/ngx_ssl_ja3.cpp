/*
 * Copyright (C) 2017-2019 Paulo Pacheco
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <algorithm>
#include <ranges>
#include <vector>
#include <span>
#include <fmt/format.h>
#include <fmt/core.h>

extern "C" {

#include "ngx_ssl_ja3.h"
#include <ngx_md5.h>

static const unsigned short GREASE[] = {
    0x0a0a,
    0x1a1a,
    0x2a2a,
    0x3a3a,
    0x4a4a,
    0x5a5a,
    0x6a6a,
    0x7a7a,
    0x8a8a,
    0x9a9a,
    0xaaaa,
    0xbaba,
    0xcaca,
    0xdada,
    0xeaea,
    0xfafa,
};


static int
ngx_ssl_ja3_is_ext_greased(int id)
{
    for (size_t i = 0; i < (sizeof(GREASE) / sizeof(GREASE[0])); ++i) {
        if (id == GREASE[i]) {
            return 1;
        }
    }
    return 0;
}


static const int nid_list[] = {
    NID_sect163k1,        /* sect163k1 (1) */
    NID_sect163r1,        /* sect163r1 (2) */
    NID_sect163r2,        /* sect163r2 (3) */
    NID_sect193r1,        /* sect193r1 (4) */
    NID_sect193r2,        /* sect193r2 (5) */
    NID_sect233k1,        /* sect233k1 (6) */
    NID_sect233r1,        /* sect233r1 (7) */
    NID_sect239k1,        /* sect239k1 (8) */
    NID_sect283k1,        /* sect283k1 (9) */
    NID_sect283r1,        /* sect283r1 (10) */
    NID_sect409k1,        /* sect409k1 (11) */
    NID_sect409r1,        /* sect409r1 (12) */
    NID_sect571k1,        /* sect571k1 (13) */
    NID_sect571r1,        /* sect571r1 (14) */
    NID_secp160k1,        /* secp160k1 (15) */
    NID_secp160r1,        /* secp160r1 (16) */
    NID_secp160r2,        /* secp160r2 (17) */
    NID_secp192k1,        /* secp192k1 (18) */
    NID_X9_62_prime192v1, /* secp192r1 (19) */
    NID_secp224k1,        /* secp224k1 (20) */
    NID_secp224r1,        /* secp224r1 (21) */
    NID_secp256k1,        /* secp256k1 (22) */
    NID_X9_62_prime256v1, /* secp256r1 (23) */
    NID_secp384r1,        /* secp384r1 (24) */
    NID_secp521r1,        /* secp521r1 (25) */
    NID_brainpoolP256r1,  /* brainpoolP256r1 (26) */
    NID_brainpoolP384r1,  /* brainpoolP384r1 (27) */
    NID_brainpoolP512r1,  /* brainpool512r1 (28) */
    EVP_PKEY_X25519,      /* X25519 (29) */
};


static unsigned short
ngx_ssl_ja3_nid_to_cid(int nid)
{
    unsigned char sz = (sizeof(nid_list) / sizeof(nid_list[0]));

    for (unsigned char i = 0; i < sz; i++) {
        if (nid == nid_list[i]) {
            return i+1;
        }
    }

    return nid;
}

#if (NGX_DEBUG)
static void
ngx_ssl_ja3_detail_print(ngx_pool_t *pool, ngx_ssl_ja3_t *ja3)
{
    /* Version */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja3: Version:  %d\n", ja3->version);

    /* Ciphers */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja3: ciphers: length: %d\n",
                   ja3->ciphers_sz);

    for (size_t i = 0; i < ja3->ciphers_sz; ++i) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja3: |    cipher: 0x%04uxD -> %d",
                       ja3->ciphers[i],
                       ja3->ciphers[i]
        );
    }

    /* Extensions */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja3: extensions: length: %d\n",
                   ja3->extensions_sz);

    for (size_t i = 0; i < ja3->extensions_sz; ++i) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja3: |    extension: 0x%04uxD -> %d",
                       ja3->extensions[i],
                       ja3->extensions[i]
        );
    }

    /* Eliptic Curves */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja3: curves: length: %d\n",
                   ja3->curves_sz);

    for (size_t i = 0; i < ja3->curves_sz; ++i) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja3: |    curves: 0x%04uxD -> %d",
                       ja3->curves[i],
                       ja3->curves[i]
        );
    }

    /* EC Format Points */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja3: formats: length: %d\n",
                   ja3->point_formats_sz);
    for (size_t i = 0; i < ja3->point_formats_sz; ++i) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja3: |    format: %d",
                       ja3->point_formats[i]
        );
    }
}
#endif


void
ngx_ssl_ja3_fp(ngx_pool_t *pool, ngx_ssl_ja3_t *ja3, ngx_str_t *out)
{
    size_t                    len = 0, cur = 0;

    if (pool == NULL || ja3 == NULL || out == NULL) {
        return;
    }

    auto ciphers = std::span(ja3->ciphers, ja3->ciphers_sz);
    auto extensions = std::span(ja3->extensions, ja3->extensions_sz);
    auto curves = std::span(ja3->curves, ja3->curves_sz);
    auto points = std::span(ja3->point_formats, ja3->point_formats_sz);

    auto ja3_string = fmt::format("{},{},{},{},{}",
            ja3->version,
            fmt::join(ciphers, "-"),
            fmt::join(extensions, "-"),
            fmt::join(curves, "-"),
            fmt::join(points, "-")
            );

    out->len = ja3_string.size();
    out->data = (unsigned char *) ngx_pnalloc(pool, out->len);
    std::copy(ja3_string.begin(), ja3_string.end(), out->data);

#if (NGX_DEBUG)
    ngx_ssl_ja3_detail_print(pool, ja3);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja3: fp: [%V]\n", out);
#endif

}


/*
   /usr/bin/openssl s_client -connect 127.0.0.1:12345 \
           -cipher "AES128-SHA" -curves secp521r1
*/
int
ngx_ssl_ja3(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja3_t *ja3) {

    SSL                           *ssl;
    size_t                         len = 0;
    unsigned short                 us = 0;

    if (! c->ssl) {
        return NGX_DECLINED;
    }

    if (! c->ssl->handshaked) {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if ( ! ssl) {
        return NGX_DECLINED;
    }

    /* SSLVersion*/
    ja3->version = SSL_version(ssl);

    /* Cipher suites */
    ja3->ciphers = NULL;
    ja3->ciphers_sz = 0;

    if (c->ssl->ciphers && c->ssl->ciphers_sz) {
        len = c->ssl->ciphers_sz * sizeof(unsigned short);
        ja3->ciphers = (short unsigned int *) ngx_pnalloc(pool, len);
        if (ja3->ciphers == NULL) {
            return NGX_DECLINED;
        }
        auto ciphers = std::span{c->ssl->ciphers, c->ssl->ciphers_sz};

        auto ungreased_ciphers = ciphers
            | std::views::transform(ntohs)
            | std::views::filter(std::not_fn(ngx_ssl_ja3_is_ext_greased));

        auto res = std::ranges::copy(ungreased_ciphers, ja3->ciphers);
        ja3->ciphers_sz = res.out - ja3->ciphers;
    }

    /* Extensions */
    ja3->extensions = NULL;
    ja3->extensions_sz = 0;
    if (c->ssl->extensions_size && c->ssl->extensions) {
        len = c->ssl->extensions_size * sizeof(int);
        ja3->extensions = (short unsigned int *) ngx_pnalloc(pool, len);
        if (ja3->extensions == NULL) {
            return NGX_DECLINED;
        }
        for (size_t i = 0; i < c->ssl->extensions_size; ++i) {
            if (! ngx_ssl_ja3_is_ext_greased(c->ssl->extensions[i])) {
                ja3->extensions[ja3->extensions_sz++] = c->ssl->extensions[i];
            }
        }
    }

    /* Elliptic curve points */
    ja3->curves = c->ssl->curves;
    ja3->curves_sz = 0;
    if (c->ssl->curves && c->ssl->curves_sz) {
        len = c->ssl->curves_sz * sizeof(int);
        ja3->curves = (short unsigned int *) ngx_pnalloc(pool, len);
        if (ja3->curves == NULL) {
            return NGX_DECLINED;
        }
        for (size_t i = 0; i < c->ssl->curves_sz; i++) {
            us = ntohs(c->ssl->curves[i]);
            if (! ngx_ssl_ja3_is_ext_greased(us)) {
                ja3->curves[ja3->curves_sz++] = ngx_ssl_ja3_nid_to_cid(c->ssl->curves[i]);
            }
        }
    }

    /* Elliptic curve point formats */
    ja3->point_formats_sz = c->ssl->point_formats_sz;
    ja3->point_formats = c->ssl->point_formats;

    return NGX_OK;
}

} /* extern "C" */
