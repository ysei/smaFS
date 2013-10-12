/* cyassl_io.c
 *
 * Copyright (C) 2006-2009 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#ifdef _WIN32_WCE
    /* On WinCE winsock2.h must be included before windows.h for socket stuff */
    #include <winsock2.h>
#endif


#include "cyassl_int.h"
#include "cyassl_error.h"
#include "asn.h"

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifndef _WIN32
    #include <sys/time.h>
    #include <sys/types.h>
    #include <errno.h>
    #include <unistd.h>
    #include <fcntl.h>
    #ifndef DEVKITPRO
        #include <sys/socket.h>
        #include <arpa/inet.h>
        #include <netinet/in.h>
        #include <netdb.h>
        #include <sys/ioctl.h>
    #endif
#endif /* _WIN32 */

#ifdef __sun
    #include <sys/filio.h>
#endif

#ifdef _WIN32
    #define SOCKET_EINVAL      WSAEINVAL
    #define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
    #define SOCKET_EAGAIN      WSAEWOULDBLOCK
    #define SOCKET_ECONNRESET  WSAECONNRESET
    #define SOCKET_EINTR       WSAEINTR
#else
    #define SOCKET_EINVAL      EINVAL
    #define SOCKET_EWOULDBLOCK EWOULDBLOCK
    #define SOCKET_EAGAIN      EAGAIN
    #define SOCKET_ECONNRESET  ECONNRESET
    #define SOCKET_EINTR       EINTR
#endif /* _WIN32 */


#ifdef DEVKITPRO
    /* from network.h */
    int net_send(int, const void*, int, unsigned int);
    int net_recv(int, void*, int, unsigned int);
    #define SEND_FUNCTION net_send
    #define RECV_FUNCTION net_recv
#else
    #define SEND_FUNCTION send
    #define RECV_FUNCTION recv
#endif


static INLINE int LastError(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

/* The receive embedded callback
 *  return : nb bytes read
 *           -1 : other errors (unexpected)
 *           -2 : WANT_READ
 *           -3 : Connexion reset
 *           -4 : interrupt
 *           -5 : connexion close
 */
int EnbedReceive(char *buf, int sz, void *ctx)
{
    int recvd;
    int err;
    int socket = *(int*)ctx;

    recvd = RECV_FUNCTION(socket, (char *)buf, sz, 0);

    if (recvd == -1) {
        err = LastError();
        if (err == SOCKET_EWOULDBLOCK ||
            err == SOCKET_EAGAIN)
            return -2;

        else if (err == SOCKET_ECONNRESET)
            return -3;

        else if (err == SOCKET_EINTR)
            return -4;

        else
            return -1;
    }
    else if (recvd == 0)
        return -5;

    return recvd;
}

/* The send embedded callback
 *  return : nb bytes sended
 *           -1 : other errors (unexpected)
 *           -2 : want write
 *           -3 : connexion reset
 *           -4 : interrupt
 */
int EmbedSend(char *buf, int sz, void *ctx)
{
    int socket = *(int*)ctx;
    int sent;
    int len = sz;

    sent = SEND_FUNCTION(socket, &buf[sz - len], len, 0);

    if (sent == -1) {
        if (LastError() == SOCKET_EWOULDBLOCK || 
            LastError() == SOCKET_EAGAIN)
            return -2;

        else if (LastError() == SOCKET_ECONNRESET)
            return -3;

        else if (LastError() == SOCKET_EINTR)
            return -4;

        else
            return -1;
    }
 
    return sent;
}

void SetCallbackIORecv_Ctx(SSL_CTX *ctx, CallbackIORecv CBIORecv) {
    ctx->CBIORecv = CBIORecv;
}

void SetCallbackIOSend_Ctx(SSL_CTX *ctx, CallbackIOSend CBIOSend) {
    ctx->CBIOSend = CBIOSend;
}

void SetCallbackIO_ReadCtx(SSL* ssl, void *rctx) {
	ssl->IOCB_ReadCtx = rctx;
}

void SetCallbackIO_WriteCtx(SSL* ssl, void *wctx) {
	ssl->IOCB_WriteCtx = wctx;
}


