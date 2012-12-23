package nl.openfortress.socket6bed4;


class Utils {

	final static byte IPPROTO_ICMPV6 = 58;
	final static byte IPPROTO_UDP = 17;
	final static byte IPPROTO_TCP = 6;
	
	final static byte ND_ROUTER_SOLICIT   = (byte) 133;
	final static byte ND_ROUTER_ADVERT    = (byte) 134;
	final static byte ND_NEIGHBOR_SOLICIT = (byte) 135;
	final static byte ND_NEIGHBOR_ADVERT  = (byte) 136;
	final static byte ND_REDIRECT         = (byte) 137;
	final static byte ND_LOWEST           = (byte) 133;
	final static byte ND_HIGHEST          = (byte) 137;
	
	final static byte ND_OPT_PREFIX_INFORMATION = 3;
	
	final static int OFS_IP6_SRC        = 8;
	final static int OFS_IP6_DST        = 24;
	final static int OFS_IP6_PLEN       = 4;
	final static int OFS_IP6_NXTHDR		= 6;
	final static int OFS_IP6_HOPS		= 7;
	final static int OFS_IP6_PLOAD		= 40;
	
	final static int OFS_UDP6_SRCPORT	= 40 + 0;
	final static int OFS_UDP6_DSTPORT	= 40 + 2;
	final static int OFS_UDP6_CSUM      = 40 + 6;
	final static int OFS_UDP6_PLEN		= 40 + 4;
	final static int OFS_UDP6_PLOAD		= 40 + 8;
	
	final static int OFS_ICMP6_TYPE		= 40 + 0;
	final static int OFS_ICMP6_CODE		= 40 + 1;
	final static int OFS_ICMP6_CSUM		= 40 + 2;
	final static int OFS_ICMP6_DATA		= 40 + 4;
	
	final static int OFS_ICMP6_NGBSOL_TARGET = 40 + 8;
	final static int OFS_ICMP6_NGBADV_TARGET = 40 + 8;
	final static int OFS_ICMP6_NGBADV_FLAGS  = 40 + 4;
		
	final static int OFS_TCP6_FLAGS	    = 13;
	final static int TCP_FLAG_SYN		= 0x02;
	final static int TCP_FLAG_ACK		= 0x01;
	
	final static byte router_solicitation [] = {
		// IPv6 header
		0x60, 0x00, 0x00, 0x00,
		16 / 256, 16 % 256, IPPROTO_ICMPV6, (byte) 255,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,		 // unspecd src
		(byte) 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, // all-rtr tgt
		// ICMPv6 header: router solicitation
		ND_ROUTER_SOLICIT, 0, 0x7a, (byte) 0xae,	// Checksum courtesy of WireShark :)
		// ICMPv6 body: reserved
		0, 0, 0, 0,
		// ICMPv6 option: source link layer address 0x0001 (end-aligned)
		0x01, 0x01, 0, 0, 0, 0, 0x00, 0x01,
	};

	final static byte router_linklocal_address [] = { (byte)0xfe,(byte)0x80,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };

	/* Retrieve an unsigned 16-bit value from a given index in a byte array and
	 * return it as an integer.
	 */
	public static int fetch_net16 (byte pkt [], int ofs16) {
		int retval = ((int) pkt [ofs16]) << 8 & 0xff00;
		retval = retval + (((int) pkt [ofs16+1]) & 0xff);
		return retval;
	}
	
	/* Calculate the ICMPv6 checksum field in a given IPv6 packet.
	 */
	public static int checksum_icmpv6 (byte pkt []) {
		return checksum_icmpv6 (pkt, 0);
	}
	public static int checksum_icmpv6 (byte pkt [], int pktofs) {
		int plen = fetch_net16 (pkt, pktofs + OFS_IP6_PLEN);
		int nxth = ((int) pkt [pktofs + 6]) & 0xff;
		// Pseudo header is IPv6 src/dst (included with packet) and plen/nxth and zeroes:
		int csum = plen + nxth;
		for (int i=8; i < OFS_IP6_PLOAD + plen; i += 2) {
			if (i != OFS_ICMP6_CSUM) {
				// Skip current checksum value
				csum += fetch_net16 (pkt, pktofs + i);
			}
		}
		// No need to treat a trailing single byte: ICMPv6 has no odd packet lengths
		csum = (csum & 0xffff) + (csum >> 16);
		csum = (csum & 0xffff) + (csum >> 16);
		csum = csum ^ 0xffff;	// 1's complement limited to 16 bits
		return csum;
	}

	/* Calculate the UDP checksum field in a given IPv6 packet.
	 */
	public static int checksum_udpv6 (byte pkt []) {
		return checksum_udpv6 (pkt, 0);
	}
	public static int checksum_udpv6 (byte pkt [], int pktofs) {
		int udplen = fetch_net16 (pkt, pktofs + OFS_UDP6_PLEN);
		int nxth = ((int) pkt [pktofs + 6]) & 0xff;
		// Pseudo header is IPv6 src/dst (included with packet) and plen/nxth and zeroes:
		int csum = udplen + nxth;
		for (int i=8; i < OFS_IP6_PLOAD + udplen; i++) {
			if ((i & 0x0001) == 0x0000) {
				if (i != OFS_UDP6_CSUM + 0) {
					csum += (((int) pkt [pktofs + i]) << 8) & 0xff00;
				}
			} else {
				if (i != OFS_UDP6_CSUM + 1) {
					csum += ((int) pkt [pktofs + i]) & 0x00ff;
				}
			}
		}
		csum = (csum & 0xffff) + (csum >> 16);
		csum = (csum & 0xffff) + (csum >> 16);
		csum = csum ^ 0xffff;	// 1's complement limited to 16 bits
		return csum;
	}
	
	public static void memcp_address (byte tgt [], int tgtofs, byte src [], int srcofs) {
		for (int i=0; i<16; i++) {
			tgt [tgtofs+i] = src [srcofs+i];
		}
	}
	
	public static boolean memdiff_addr (byte one[], int oneofs, byte oth[], int othofs) {
		for (int i=0; i<16; i++) {
			if (one [oneofs + i] != oth [othofs + i]) {
				return true;
			}
		}
		return false;
	}
	
	public static boolean memdiff_halfaddr (byte one[], int oneofs, byte oth[], int othofs) {
		for (int i=0; i<8; i++) {
			if (one [oneofs + i] != oth [othofs + i]) {
				return true;
			}
		}
		return false;
	}

}

