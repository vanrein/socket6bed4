package nl.openfortress.socket6bed4;

import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.UnknownHostException;


/** The Inet6bed4Address class acts a bit like InetAddress and
 * Inet6Address.  It is not, however related to these classes;
 * they are locked down by the Java language [1].  There are
 * a few calls similar to those in Inet*Address that are also
 * available here; however, an address created here will be an
 * Inet6Address.
 *
 *  [1] Inet6Address is a final class, and InetAddress has no
 *      constructors to call.  Nasty.
 */
public final class Inet6bed4Address {

	/** Returns the shared 6bed4 address for this host.
	 * Note that a 6bed4 address is available on any host that
	 * has an IPv4 address and supports IPv6.  This is also the
	 * when a native IPv6 address exists.  You should however
	 * prefer native IPv6 over 6bed4, except perhaps for the
	 * communication with 6bed4 peers.
	 */
	public static Inet6Address getLocalHost ()
	throws UnknownHostException {
		return ConnectionPool.
			getSharedConnectionPool ().
			getDefaultServerNode ().
			getShared6bed4Address ();
	}

	/** Test if a given InetAddress is a 6bed4 address.
	 * Note that this does not guarantee that it can be cast
	 * to an Inet6bed4Address.
	 * TODO: See notes for is6bed4Address(byte addr[])
	 */
	public static boolean is6bed4Address (Inet6Address ia) {
		if (! (ia instanceof Inet6Address)) {
			return false;
		}
		//TODO// Quickfix to incorporate active servers, ideally also to be done for the byte[] version, and would ideally not be limited to the shared pool:
		if (ConnectionPool.getSharedConnectionPool ().getServerNode (ia) != null) {
			return true;
		}
		return is6bed4Address (ia.getAddress ());
	}

	/** Test if the given byte array represents a 6bed4 address.
	 * TODO: These addresses are subject to change until 6bed4
	 * is formalised as an RFC!  Please subscribe to
	 * tun6bed4-infra for (only those) updates:
	 * https://lists.sourceforge.net/lists/listinfo/tun6bed4-infra
	 * The intention is to obtain a /16 for ten years to come,
	 * and recognise a 6bed4 address based on that.
	 */
	public static boolean is6bed4Address (byte addr[]) {
		if (addr.length != 16) {
			return false;
		}
		//TODO// Take local 6bed4 serverpool into account
		return
            (addr [0] & 0xff) == 0x2a &&
            (addr [1] & 0xff) == 0x01 &&
            (addr [2] & 0xff) == 0x04 &&
            (addr [3] & 0xff) == 0xf8 &&
            (addr [4] & 0xff) == 0x0d &&
            (addr [5] & 0xff) == 0x12 &&
            (addr [6] & 0xff) == 0x1c &&
            (addr [7] & 0xff) == 0xc1;
	}

	/** Return an Inet6bed4Address based on a byte string.
	 * TODO: Perhaps try sharing with existing instances?
	 */
	public static Inet6Address getByAddress (byte addr[]) {
		//TODO// Instead of just checking length, eventually use is6bed4Address
		if (addr.length != 16) {
			throw new ClassCastException ("Byte array has wrong length");
		}
		if (!is6bed4Address (addr)) {
			throw new ClassCastException ("Address is not a 6bed4 address");
		}
		try {
			return (Inet6Address) InetAddress.getByAddress (addr);
		} catch (UnknownHostException uhe) {
			throw new RuntimeException ("Failed to parse IPv6 address bytes");
		}
	}

	/** A private constructor avoids instantiation.
	 */
	private Inet6bed4Address () {
		;
	}

}

