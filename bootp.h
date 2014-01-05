//bootp.h

#include <sys/cdefs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/udp.h>


#define iaddr_t struct in_addr

struct bootp {
	u_char	bp_op;		/* packet opcode type */
#define	BOOTREQUEST	1
#define	BOOTREPLY	2
	u_char	bp_htype;	/* hardware addr type */
	u_char	bp_hlen;	/* hardware addr length */
	u_char	bp_hops;	/* gateway hops */
	u_int32_t bp_xid;	/* transaction ID */
	u_short	bp_secs;	/* seconds since boot began */	
	u_short	bp_unused;
	iaddr_t	bp_ciaddr;	/* client IP address */
	iaddr_t	bp_yiaddr;	/* 'your' IP address */
	iaddr_t	bp_siaddr;	/* server IP address */
	iaddr_t	bp_giaddr;	/* gateway IP address */
	u_char	bp_chaddr[16];	/* client hardware address */
	u_char	bp_sname[64];	/* server host name */
	u_char	bp_file[128];	/* boot file name */
	u_char	bp_vend[64];	/* vendor-specific area */
};
