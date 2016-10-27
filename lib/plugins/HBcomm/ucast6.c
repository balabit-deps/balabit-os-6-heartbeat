/*
 * ucast6.c: implements heartbeat API for UPD IPv6 unicast communication
 *
 * Copyright (C) 2014 Linbit HA Solutions GmbH
 * written by Lars Ellenberg <lars@linbit.com>
 * based on ucast.c and mcast6.c, see there.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <lha_internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <HBcomm.h>

/*
 * Plugin information
 */
#define PIL_PLUGINTYPE		HB_COMM_TYPE
#define PIL_PLUGINTYPE_S	HB_COMM_TYPE_S
#define PIL_PLUGIN		ucast6
#define PIL_PLUGIN_S		"ucast6"
#define PIL_PLUGINLICENSE	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL	URL_LGPL
#include <pils/plugin.h>
#include <heartbeat.h>

static int largest_msg_size = 0;

/* sizeof ucast6_s:
 * INET6_ADDRSTRLEN (48) + '%' + IF_NAMESIZE (16),
 * both contain padding already.
 * [0000:0000:0000:0000:0000:ffff:255.255.255.255%someinterface]
 * 64 should be good enought, but round up to 80
 * in case we want to store :port in there as well */
struct ucast6_private {
	char*	interface;		/* Interface name */
	char	ucast6_s[80];		/* target address and port */
	struct	sockaddr_in6   paddr;	/* peer addr */
	struct	sockaddr_in6   saddr;	/* local addr to bind() to */
	int rsocket;			/* Read-socket */
	int wsocket;			/* Write-socket */
};

/* config parameter udpport, default ha-cluster resp. 694 */
static unsigned int udp_port;

static int		ucast6_parse(const char* configline);
static struct hb_media * ucast6_new(const char * intf, const char *ucast6);
static int		ucast6_open(struct hb_media* mp);
static int		ucast6_close(struct hb_media* mp);
static void*		ucast6_read(struct hb_media* mp, int* lenp);
static int		ucast6_write(struct hb_media* mp, void* p, int len);
static int		ucast6_descr(char** buffer);
static int		ucast6_mtype(char** buffer);
static int		ucast6_isping(void);


static struct hb_media_fns ucast6Ops ={
	NULL,		/* Create single object function */
	ucast6_parse,	/* whole-line parse function */
	ucast6_open,
	ucast6_close,
	ucast6_read,
	ucast6_write,
	ucast6_mtype,
	ucast6_descr,
	ucast6_isping,
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)
static const PILPluginImports*	PluginImports;
static PILPlugin*		OurPlugin;
static PILInterface*		OurInterface;
static struct hb_media_imports*	OurImports;
static void*			interfprivate;

#define LOG	PluginImports->log
#define MALLOC	PluginImports->alloc
#define STRDUP	PluginImports->mstrdup
#define FREE	PluginImports->mfree

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, const PILPluginImports* imports);

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, const PILPluginImports* imports)
{
	/* Force the compiler to do a little type checking */
	(void)(PILPluginInitFun)PIL_PLUGIN_INIT;

	PluginImports = imports;
	OurPlugin = us;

	/* Register ourself as a plugin */
	imports->register_plugin(us, &OurPIExports);

	/*  Register our interface implementation */
	return imports->register_interface(us, PIL_PLUGINTYPE_S
	,	PIL_PLUGIN_S
	,	&ucast6Ops
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	interfprivate);
}

/* helper functions */
static int ucast6_make_receive_sock(struct hb_media* hbm);
static int ucast6_make_send_sock(struct hb_media * hbm);
static struct ucast6_private* new_ucast6_private(const char *ifn, const char *ucast6);
static int is_valid_dev(const char *dev);
static int is_valid_ucast6_addr(const char *addr);
#define		ISUCASTOBJECT(p) ((p) && ((p)->vf == (void*)&ucast6Ops))
#define		UCASTASSERT(p)	g_assert(ISUCASTOBJECT(p))

static int
ucast6_mtype(char** buffer)
{
	*buffer = STRDUP(PIL_PLUGIN_S);
	if (!*buffer) {
		return 0;
	}

	return STRLEN_CONST(PIL_PLUGIN_S);
}

static int
ucast6_descr(char **buffer)
{
	const char cret[] = "UDP/IPv6 unicast";
	*buffer = STRDUP(cret);
	if (!*buffer) {
		return 0;
	}

	return STRLEN_CONST(cret);
}

static int
ucast6_isping(void)
{
	/* nope, this is not a ping device */
	return 0;
}

/* ucast6_parse will parse the line in the config file that is
 * associated with the media's type (hb_dev_mtype).  It should
 * receive the rest of the line after the mtype.  And it needs
 * to call hb_dev_new, add the media to the list of available media.
 *
 * So in this case, the config file line should look like
 * ucast6 [device] [ucast6 address]
 */
#define GET_NEXT_TOKEN(bp, token) do {		 \
	int toklen;				 \
	bp += strspn(bp, WHITESPACE);		 \
	toklen = strcspn(bp, WHITESPACE);	 \
	strncpy(token, bp, toklen);		 \
	bp += toklen;				 \
	token[toklen] = EOS;			 \
} while(0)

static int
ucast6_parse(const char *line)
{
	const char *		bp = line;
	char			dev[MAXLINE];
	char			ucast6[MAXLINE];
	struct hb_media *	mp;

	GET_NEXT_TOKEN(bp, dev);
	if (*dev == EOS) {
		PILCallLog(LOG, PIL_CRIT, "ucast6 statement without device");
		return HA_FAIL;
	}

	if (!is_valid_dev(dev)) {
		PILCallLog(LOG, PIL_CRIT, "ucast6 device [%s] is invalid or not set up properly", dev);
		return HA_FAIL;
	}

	GET_NEXT_TOKEN(bp, ucast6);
	if (*ucast6 == EOS)  {
		PILCallLog(LOG, PIL_CRIT, "ucast6 [%s] missing ucast6 address", dev);
		return(HA_FAIL);
	}
	if (!is_valid_ucast6_addr(ucast6)) {
		PILCallLog(LOG, PIL_CRIT, "ucast6 [%s] bad addr [%s]", dev, ucast6);
		return(HA_FAIL);
	}

	if ((mp = ucast6_new(dev, ucast6)) == NULL) {
		return(HA_FAIL);
	}
	OurImports->RegisterNewMedium(mp);

	return(HA_OK);
}

static int get_udpport(void)
{
	struct servent *service;
	const char *chport;

	if (udp_port > 0)
		return HA_OK;

	chport = OurImports->ParamValue("udpport");
	if (chport) {
		if (sscanf(chport, "%u", &udp_port) <= 0
		    || udp_port <= 0 || udp_port > 0xffff) {
			PILCallLog(LOG, PIL_CRIT,
				"ucast6: bad port number %s", chport);
			return HA_FAIL;
		}
		return HA_OK;
	}

	/* No port specified in the configuration... */

	/* If our service name is in /etc/services, then use it */
	service = getservbyname(HA_SERVICENAME, "udp");
	if (service)
		udp_port = ntohs(service->s_port);
	else
		udp_port = UDPPORT;
	return HA_OK;
}

/*
 * Create new UDP/IPv6 unicast heartbeat object
 * pass in name of interface and peer address
 * This should get called from hb_dev_parse().
 */
static struct hb_media *
ucast6_new(const char * intf, const char *ucast6)
{
	struct ucast6_private*	ucp;
	struct hb_media *	ret;

	/* create new ucast6_private struct...hmmm...who frees it? */
	ucp = new_ucast6_private(intf, ucast6);
	if (ucp == NULL) {
		PILCallLog(LOG, PIL_WARN, "Error creating ucast6_private(%s, %s)",
			 intf, ucast6);
		return NULL;
	}
	ret = (struct hb_media*) MALLOC(sizeof(struct hb_media));
	if (ret != NULL) {
		char * name;
		memset(ret, 0, sizeof(*ret));
		ret->pd = (void*)ucp;
		name = STRDUP(intf);
		if (name != NULL) {
			ret->name = name;
		}
		else {
			FREE(ret);
			ret = NULL;
		}

	}
	if (ret == NULL) {
		FREE(ucp->interface);
		FREE(ucp);
	}
	return ret;
}

/*
 *	Open UDP/IP unicast heartbeat interface
 */
static int
ucast6_open(struct hb_media* hbm)
{
	struct ucast6_private * ucp;

	UCASTASSERT(hbm);
	ucp = (struct ucast6_private *) hbm->pd;

	if ((ucp->wsocket = ucast6_make_send_sock(hbm)) < 0) {
		return(HA_FAIL);
	}
	if (Debug) {
		PILCallLog(LOG, PIL_DEBUG
		,	"%s: write socket: %d"
		,	__FUNCTION__, ucp->wsocket);
	}
	if ((ucp->rsocket = ucast6_make_receive_sock(hbm)) < 0) {
		ucast6_close(hbm);
		return(HA_FAIL);
	}
	if (Debug) {
		PILCallLog(LOG, PIL_DEBUG
		,	"%s: read socket: %d"
		,	__FUNCTION__, ucp->rsocket);
	}

	PILCallLog(LOG, PIL_INFO, "ucast6: heartbeat started for [%s]:%u "
		"on interface %s" ,
		ucp->ucast6_s, udp_port, ucp->interface);

	return(HA_OK);
}

/*
 *	Close UDP/IP unicast heartbeat interface
 */
static int
ucast6_close(struct hb_media* hbm)
{
	struct ucast6_private * ucp;
	int	rc = HA_OK;

	UCASTASSERT(hbm);
	ucp = (struct ucast6_private *) hbm->pd;

	if (ucp->rsocket >= 0) {
		if (Debug) {
			PILCallLog(LOG, PIL_DEBUG
			,	"%s: Closing socket %d"
			,	__FUNCTION__, ucp->rsocket);
		}
		if (close(ucp->rsocket) < 0) {
			rc = HA_FAIL;
		}
		ucp->rsocket = -1;
	}
	if (ucp->wsocket >= 0) {
		if (Debug) {
			PILCallLog(LOG, PIL_DEBUG
			,	"%s: Closing socket %d"
			,	__FUNCTION__, ucp->wsocket);
		}
		if (close(ucp->wsocket) < 0) {
			rc = HA_FAIL;
		}
		ucp->rsocket = -1;
	}
	return(rc);
}

/*
 * Receive a heartbeat unicast packet from UDP interface
 */

char			ucast6_pkt[MAXMSG];
static void *
ucast6_read(struct hb_media* hbm, int *lenp)
{
	struct ucast6_private *	ucp;
	socklen_t		addr_len = sizeof(struct sockaddr);
	struct sockaddr_in	their_addr; /* connector's addr information */
	int	numbytes;

	UCASTASSERT(hbm);
	ucp = (struct ucast6_private *) hbm->pd;

	if ((numbytes=recvfrom(ucp->rsocket, ucast6_pkt, MAXMSG-1, 0
	,	(struct sockaddr *)&their_addr, &addr_len)) < 0) {
		if (errno != EINTR) {
			PILCallLog(LOG, PIL_CRIT, "ucast6: Error receiving from socket: %s"
			    ,	strerror(errno));
		}
		return NULL;
	}
	/* Avoid possible buffer overruns */
	ucast6_pkt[numbytes] = EOS;

	if (numbytes > largest_msg_size) {
		PILCallLog(LOG, PIL_DEBUG, "ucast6: maximum received message: %d bytes from %s", numbytes, ucp->ucast6_s);
		largest_msg_size = numbytes;
	}
	if (Debug >= PKTTRACE) {
		PILCallLog(LOG, PIL_DEBUG, "got %d byte packet from %s"
		    ,	numbytes, inet_ntoa(their_addr.sin_addr));
	}
	if (Debug >= PKTCONTTRACE && numbytes > 0) {
		PILCallLog(LOG, PIL_DEBUG, "%s", ucast6_pkt);
	}

	*lenp = numbytes + 1 ;

	return ucast6_pkt;;
}

/*
 * Send a heartbeat packet over unicast UDP/IP interface
 */

static int
ucast6_write(struct hb_media* hbm, void *pkt, int len)
{
	struct ucast6_private *	ucp;
	int			rc;

	UCASTASSERT(hbm);
	ucp = (struct ucast6_private *) hbm->pd;

	rc = sendto(ucp->wsocket, pkt, len, 0
	,	(struct sockaddr *)&ucp->paddr, sizeof(struct sockaddr_in6));
	if (rc != len) {
		if (!hbm->suppresserrs) {
			PILCallLog(LOG, PIL_CRIT
			,	"%s: Unable to send " PIL_PLUGINTYPE_S " packet %s[%s]:%u len=%d [%d]: %s"
			,	__FUNCTION__, ucp->interface, ucp->ucast6_s, udp_port
			,	len, rc, strerror(errno));
		}
		return(HA_FAIL);
	}

	if (len > largest_msg_size) {
		PILCallLog(LOG, PIL_DEBUG, "ucast6: maximum sent message: %d bytes to %s", rc, ucp->ucast6_s);
		largest_msg_size = len;
	}

	if (Debug >= PKTTRACE) {
		PILCallLog(LOG, PIL_DEBUG, "sent %d bytes to %s", rc, ucp->ucast6_s);
	}
	if (Debug >= PKTCONTTRACE) {
		PILCallLog(LOG, PIL_DEBUG, "%s", (const char *)pkt);
	}
	return(HA_OK);
}

static void
adjust_socket_bufs(int sockfd, int bytes)
{
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
	/* FIXME error handling, logging */
}

/*
 * Set up socket for sending unicast UDP heartbeats
 */

static int
ucast6_make_send_sock(struct hb_media * hbm)
{
	int sockfd;
	struct ucast6_private * ucp;
	UCASTASSERT(hbm);
	ucp = (struct ucast6_private *) hbm->pd;

	if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		PILCallLog(LOG, PIL_WARN, "Error getting socket: %s", strerror(errno));
		return(sockfd);
	}
	adjust_socket_bufs(sockfd, 1024*1024);
#if defined(SO_BINDTODEVICE)
	{
		/*
		 *  We want to receive packets only from this interface...
		 */
		struct ifreq i;
		strcpy(i.ifr_name,  ucp->interface);

		if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
				&i, sizeof(i)) == -1) {
			PILCallLog(LOG, PIL_CRIT,
			  "ucast6: error setting option SO_BINDTODEVICE(r) on %s: %s",
			  i.ifr_name, strerror(errno));
			close(sockfd);
			return -1;
		}
		PILCallLog(LOG, PIL_INFO, "ucast6: bound send socket to device: %s",
			i.ifr_name);
	}
#endif

	if (fcntl(sockfd,F_SETFD, FD_CLOEXEC)) {
		PILCallLog(LOG, PIL_WARN, "ucast6: Error setting the close-on-exec flag: %s", strerror(errno));
	}
	return(sockfd);
}

/*
 * Set up socket for listening to heartbeats (UDP unicasts)
 */

#define	MAXBINDTRIES	50
static int
ucast6_make_receive_sock(struct hb_media * hbm)
{
	struct ucast6_private * ucp;
	int	sockfd;
	int	bindtries;
	int	boundyet=0;
	int	one=1;
	int	rc;
	int	error=0;

	UCASTASSERT(hbm);
	ucp = (struct ucast6_private *) hbm->pd;

	if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		PILCallLog(LOG, PIL_CRIT, "ucast6: Error getting socket");
		return -1;
	}
	/* set REUSEADDR option on socket so you can bind a unicast */
	/* reader to multiple interfaces */
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one)) < 0){
		PILCallLog(LOG, PIL_CRIT, "ucast6: Error setsockopt(SO_REUSEADDR)");
	}
	adjust_socket_bufs(sockfd, 1024*1024);
#if defined(SO_BINDTODEVICE)
	{
		/*
		 *  We want to receive packets only from this interface...
		 */
		struct ifreq i;
		strcpy(i.ifr_name,  ucp->interface);

		if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
				&i, sizeof(i)) == -1) {
			PILCallLog(LOG, PIL_CRIT,
			  "ucast6: error setting option SO_BINDTODEVICE(r) on %s: %s",
			  i.ifr_name, strerror(errno));
			close(sockfd);
			return -1;
		}
		PILCallLog(LOG, PIL_INFO, "ucast6: bound receive socket to device: %s",
			i.ifr_name);
	}
#endif
#if defined(SO_REUSEPORT)
	/*
	 *  Needed for OpenBSD for more than two nodes in a ucast cluster
	 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
			&one, sizeof(one)) == -1) {
		/*
		 * Linux learned SO_REUSEPORT only with kernel 3.9,
		 * but some linux headers already define SO_REUSEPORT.
		 * Which will result in ENOPROTOOPT, "Protocol not available"
		 * on older kernels.
		 * Failure to set SO_REUSEPORT is NOT critical in general.
		 * It *may* be a problem on certain BSDs with more than
		 * two nodes all using ucast.
		 * Refusing to start because of failure to set SO_REUSEPORT is
		 * not helpful for the vast majority of the clusters out there.
		 */
		if (errno == ENOPROTOOPT) {
			PILCallLog(LOG, PIL_WARN,
			  "ucast6: error setting option SO_REUSEPORT: %s", strerror(errno));
		} else {
			PILCallLog(LOG, PIL_CRIT,
			  "ucast6: error setting option SO_REUSEPORT: %s", strerror(errno));
			return -1;
		}
	} else
		PILCallLog(LOG, PIL_INFO, "ucast6: set SO_REUSEPORT");
#endif

	/* ripped off from udp.c, if we all use SO_REUSEADDR */
	/* this shouldn't be necessary	*/
	/* Try binding a few times before giving up */
	/* Sometimes a process with it open is exiting right now */

	for(bindtries=0; !boundyet && bindtries < MAXBINDTRIES; ++bindtries) {
		rc = bind(sockfd, (void*)&ucp->saddr, sizeof(ucp->saddr));
		error = errno;
		if (rc == 0) {
			boundyet=1;
		} else if (rc == -1) {
			if (error == EADDRINUSE) {
				PILCallLog(LOG, PIL_CRIT, "ucast6: Can't bind (EADDRINUSE), retrying");
				sleep(1);
			} else	{
			/* don't keep trying if the error isn't caused by */
			/* the address being in use already...real error */
				break;
			}
		}
	}
	if (!boundyet) {
		PILCallLog(LOG, PIL_WARN, "ucast6: Unable to bind socket to %s %u. Giving up: %s",
			ucp->ucast6_s, udp_port, strerror(errno));
		close(sockfd);
		return -1;
	}
	if (fcntl(sockfd,F_SETFD, FD_CLOEXEC)) {
		PILCallLog(LOG, PIL_WARN, "ucast6: Error setting the close-on-exec flag: %s", strerror(errno));
	}
	return sockfd;
}

static int is_link_local(struct in6_addr *addr)
{
	/* fe80::/10 */
	return	 addr->s6_addr[0] == 0xfe &&
		(addr->s6_addr[1] & 0xc0) == 0x80;
}

static struct ucast6_private *
new_ucast6_private(const char *ifn, const char *ucast6)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct ucast6_private *ucp;
	char port[8];
	int error;

	get_udpport();
	snprintf(port, sizeof(port), "%u", udp_port);

	ucp = MALLOCT(struct ucast6_private);
	if (ucp == NULL)  {
		return NULL;
	}
	memset(ucp, 0, sizeof(*ucp));

	ucp->interface = (char *)STRDUP(ifn);
	if(ucp->interface == NULL) {
		FREE(ucp);
		return NULL;
	}

	/* ucast group destination address */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(ucast6, port, &hints, &res);
	if (error) {
		PILCallLog(LOG, PIL_CRIT, "getaddrinfo([%s]:%s): %s",
			ucast6, port, gai_strerror(error));
		goto getout;
	}
	memcpy(&ucp->paddr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	/* store canonicalized input as char* again. */
	inet_ntop(AF_INET6, &ucp->paddr.sin6_addr,
		ucp->ucast6_s, sizeof(ucp->ucast6_s));

	/* do we need the "scope id"? */
	if (is_link_local(&ucp->paddr.sin6_addr)) {
		unsigned int len;
		unsigned int if_idx = if_nametoindex(ifn);
		if (if_idx == 0) {
			/* Has just now been checked in is_valid_dev(),
			 * failing here should be extremely unlikely. */
			PILCallLog(LOG, PIL_CRIT, "ucast6: device %s just vanished?", ifn);
			goto getout;
		}
		/* implicitly set, if link-local address was specified without %scope-id. */
		if (ucp->paddr.sin6_scope_id == 0)
			ucp->paddr.sin6_scope_id = if_idx;
		else if (ucp->paddr.sin6_scope_id != if_idx) {
			PILCallLog(LOG, PIL_CRIT,
				"ucast6: index %u does not match scope id %u for device %s",
				if_idx, ucp->paddr.sin6_scope_id, ifn);
			goto getout;
		}
		
		len = strlen(ucp->ucast6_s);
		if (len + strlen(ifn) < sizeof(ucp->ucast6_s))
			snprintf(ucp->ucast6_s + len, sizeof(ucp->ucast6_s) - len, "%%%s", ifn);
	}

	/* local address to bind() to, results usually in [::]:someport */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(NULL, port, &hints, &res);
	if (error) {
		PILCallLog(LOG, PIL_CRIT, "getaddrinfo([::]:%s): %s",
			port, gai_strerror(error));
		goto getout;
	}
	memcpy(&ucp->saddr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	ucp->wsocket = -1;
	ucp->rsocket = -1;
	return ucp;

getout:
	FREE(ucp->interface);
	FREE(ucp);
	return NULL;
}

/* returns true or false */
static int
is_valid_dev(const char *dev)
{
	int rc=0;
	if (dev) {
		if (if_nametoindex(dev) > 0)
			rc = 1;
	}
	return rc;
}

/* returns true or false */
static int
is_valid_ucast6_addr(const char *addr)
{
	unsigned char uc6_addr[sizeof(struct in6_addr)];
	int i;
	char tmp_addr[INET6_ADDRSTRLEN+1];

	/* don't want to do getaddrinfo lookup, but inet_pton get's confused by
	 * %eth0 link local scope specifiers. So we have a temporary copy
	 * without that part. */
	for (i=0; addr[i] && addr[i] != '%' && i < INET6_ADDRSTRLEN; i++)
		tmp_addr[i] = addr[i];
	tmp_addr[i] = 0;

	if (inet_pton(AF_INET6, tmp_addr, &uc6_addr) <= 0)
		return 0;

	/* http://tools.ietf.org/html/rfc3513#section-2.7 */
	/* multicast is not valid here */
	if (uc6_addr[0] == 0xff)
		return 0;

	/* "Unspecified" ? */
	if (!memcmp(uc6_addr, "\0\0\0\0" "\0\0\0\0" "\0\0\0\0" "\0\0\0\0", 16))
		return 0;

	/* "Loopback" ? */
	if (!memcmp(uc6_addr, "\0\0\0\0" "\0\0\0\0" "\0\0\0\0" "\0\0\0\x01", 16))
		return 0;

	/* still here? plausibility check passed */
	return 1;
}
