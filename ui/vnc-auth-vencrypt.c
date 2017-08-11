/*
 * QEMU VNC display driver: VeNCrypt authentication setup
 *
 * Copyright (C) 2006 Anthony Liguori <anthony@codemonkey.ws>
 * Copyright (C) 2006 Fabrice Bellard
 * Copyright (C) 2009 Red Hat, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "vnc.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"
#include "io/channel-socket.h"

static int protocol_client_auth_plain(VncState *vs, uint8_t *data, size_t len)
{
	Error *err = NULL;
	char username[256];
	char passwd[512];

	SocketAddress *clientip = qio_channel_socket_get_remote_address(vs->sioc, &err);
	if (err) {
	    goto err;
	}

	if ((len != (vs->username_len + vs->password_len)) ||
	    (vs->username_len >= (sizeof(username)-1)) ||
	    (vs->password_len >= (sizeof(passwd)-1))	) {
		error_setg(&err, "Got unexpected data length");
		goto err;
	}

	strncpy(username, (char *)data, vs->username_len);
	username[vs->username_len] = 0;
	strncpy(passwd, (char *)data + vs->username_len, vs->password_len);
	passwd[vs->password_len] = 0;

	VNC_DEBUG("AUTH PLAIN username: %s pw: %s\n", username, passwd);

	if (pve_auth_verify(clientip->u.inet.host, username, passwd) == 0) {
		vnc_write_u32(vs, 0); /* Accept auth completion */
		start_client_init(vs);
		qapi_free_SocketAddress(clientip);
		return 0;
	}

	error_setg(&err, "Authentication failed");
err:
       if (err) {
	       const char *err_msg = error_get_pretty(err);
	       VNC_DEBUG("AUTH PLAIN ERROR: %s\n", err_msg);
	       vnc_write_u32(vs, 1); /* Reject auth */
	       if (vs->minor >= 8) {
		       int elen = strlen(err_msg);
		       vnc_write_u32(vs, elen);
		       vnc_write(vs, err_msg, elen);
	       }
	       error_free(err);
       }
       vnc_flush(vs);
       vnc_client_error(vs);

       qapi_free_SocketAddress(clientip);

       return 0;

}

static int protocol_client_auth_plain_start(VncState *vs, uint8_t *data, size_t len)
{
	uint32_t ulen = read_u32(data, 0);
	uint32_t pwlen = read_u32(data, 4);
	const char *err = NULL;

	VNC_DEBUG("AUTH PLAIN START %u %u\n", ulen, pwlen);

       if (!ulen) {
	       err = "No User name.";
	       goto err;
       }
       if (ulen >= 255) {
	       err = "User name too long.";
	       goto err;
       }
       if (!pwlen) {
	       err = "Password too short";
	       goto err;
       }
       if (pwlen >= 511) {
	       err = "Password too long.";
	       goto err;
       }

       vs->username_len = ulen;
       vs->password_len = pwlen;

       vnc_read_when(vs, protocol_client_auth_plain, ulen + pwlen);

       return 0;
err:
       if (err) {
	       VNC_DEBUG("AUTH PLAIN ERROR: %s\n", err);
	       vnc_write_u32(vs, 1); /* Reject auth */
	       if (vs->minor >= 8) {
		       int elen = strlen(err);
		       vnc_write_u32(vs, elen);
		       vnc_write(vs, err, elen);
	       }
       }
       vnc_flush(vs);
       vnc_client_error(vs);

       return 0;
}

static void start_auth_vencrypt_subauth(VncState *vs)
{
    switch (vs->subauth) {
    case VNC_AUTH_VENCRYPT_TLSNONE:
    case VNC_AUTH_VENCRYPT_X509NONE:
       VNC_DEBUG("Accept TLS auth none\n");
       vnc_write_u32(vs, 0); /* Accept auth completion */
       start_client_init(vs);
       break;

    case VNC_AUTH_VENCRYPT_TLSPLAIN:
    case VNC_AUTH_VENCRYPT_X509PLAIN:
       VNC_DEBUG("Start TLS auth PLAIN\n");
       vnc_read_when(vs, protocol_client_auth_plain_start, 8);
       break;

    case VNC_AUTH_VENCRYPT_PLAIN:
       VNC_DEBUG("Start auth PLAIN\n");
       vnc_read_when(vs, protocol_client_auth_plain_start, 8);
       break;

    case VNC_AUTH_VENCRYPT_TLSVNC:
    case VNC_AUTH_VENCRYPT_X509VNC:
       VNC_DEBUG("Start TLS auth VNC\n");
       start_auth_vnc(vs);
       break;

#ifdef CONFIG_VNC_SASL
    case VNC_AUTH_VENCRYPT_TLSSASL:
    case VNC_AUTH_VENCRYPT_X509SASL:
      VNC_DEBUG("Start TLS auth SASL\n");
      start_auth_sasl(vs);
      break;
#endif /* CONFIG_VNC_SASL */

    default: /* Should not be possible, but just in case */
       VNC_DEBUG("Reject subauth %d server bug\n", vs->auth);
       vnc_write_u8(vs, 1);
       if (vs->minor >= 8) {
           static const char err[] = "Unsupported authentication type";
           vnc_write_u32(vs, sizeof(err));
           vnc_write(vs, err, sizeof(err));
       }
       vnc_client_error(vs);
    }
}

static void vnc_tls_handshake_done(QIOTask *task,
                                   gpointer user_data)
{
    VncState *vs = user_data;
    Error *err = NULL;

    if (qio_task_propagate_error(task, &err)) {
        VNC_DEBUG("Handshake failed %s\n",
                  error_get_pretty(err));
        vnc_client_error(vs);
        error_free(err);
    } else {
        vs->ioc_tag = qio_channel_add_watch(
            vs->ioc, G_IO_IN | G_IO_OUT, vnc_client_io, vs, NULL);
        start_auth_vencrypt_subauth(vs);
    }
}


static int protocol_client_vencrypt_auth(VncState *vs, uint8_t *data, size_t len)
{
    int auth = read_u32(data, 0);

    if (auth != vs->subauth && auth != VNC_AUTH_VENCRYPT_PLAIN) {
        VNC_DEBUG("Rejecting auth %d\n", auth);
        vnc_write_u8(vs, 0); /* Reject auth */
        vnc_flush(vs);
        vnc_client_error(vs);
    } else {
        if (auth == VNC_AUTH_VENCRYPT_PLAIN) {
            vs->subauth = auth;
            start_auth_vencrypt_subauth(vs);
        }
        else
        {
            Error *err = NULL;
            QIOChannelTLS *tls;
            VNC_DEBUG("Accepting auth %d, setting up TLS for handshake\n", auth);
            vnc_write_u8(vs, 1); /* Accept auth */
            vnc_flush(vs);

            if (vs->ioc_tag) {
                g_source_remove(vs->ioc_tag);
                vs->ioc_tag = 0;
            }

            tls = qio_channel_tls_new_server(
                vs->ioc,
                vs->vd->tlscreds,
                vs->vd->tlsaclname,
                &err);
            if (!tls) {
                VNC_DEBUG("Failed to setup TLS %s\n", error_get_pretty(err));
                error_free(err);
                vnc_client_error(vs);
                return 0;
                vs->tls = qcrypto_tls_session_new(vs->vd->tlscreds,
                                                  NULL,
                                                  vs->vd->tlsaclname,
                                                  QCRYPTO_TLS_CREDS_ENDPOINT_SERVER,
                                                  &err);
                if (!vs->tls) {
                    VNC_DEBUG("Failed to setup TLS %s\n",
                              error_get_pretty(err));
                    error_free(err);
                    vnc_client_error(vs);
                    return 0;
                }
            }
            qio_channel_set_name(QIO_CHANNEL(tls), "vnc-server-tls");

            VNC_DEBUG("Start TLS VeNCrypt handshake process\n");
            object_unref(OBJECT(vs->ioc));
            vs->ioc = QIO_CHANNEL(tls);
            vs->tls = qio_channel_tls_get_session(tls);

            qio_channel_tls_handshake(tls,
                                      vnc_tls_handshake_done,
                                      vs,
                                      NULL);
        }
    }
    return 0;
}

static int protocol_client_vencrypt_init(VncState *vs, uint8_t *data, size_t len)
{
    if (data[0] != 0 ||
        data[1] != 2) {
        VNC_DEBUG("Unsupported VeNCrypt protocol %d.%d\n", (int)data[0], (int)data[1]);
        vnc_write_u8(vs, 1); /* Reject version */
        vnc_flush(vs);
        vnc_client_error(vs);
    } else {
        VNC_DEBUG("Sending allowed auths %d %d\n", vs->subauth, VNC_AUTH_VENCRYPT_PLAIN);
        vnc_write_u8(vs, 0); /* Accept version */
        vnc_write_u8(vs, 2); /* Number of sub-auths */
        vnc_write_u32(vs, vs->subauth); /* The supported auth */
        vnc_write_u32(vs, VNC_AUTH_VENCRYPT_PLAIN); /* Alternative supported auth */
        vnc_flush(vs);
        vnc_read_when(vs, protocol_client_vencrypt_auth, 4);
    }
    return 0;
}


void start_auth_vencrypt(VncState *vs)
{
    /* Send VeNCrypt version 0.2 */
    vnc_write_u8(vs, 0);
    vnc_write_u8(vs, 2);

    vnc_read_when(vs, protocol_client_vencrypt_init, 2);
}

