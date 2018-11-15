package nl.openfortress.socket6bed4;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import java.util.Hashtable;


/** The ConnectionPool links IPv4 sockets for 6bed4 with the implementations
 * of IPv6 sockets.  Each IPv4 socket may have multiple IPv6 sockets, as
 * a result of these variation factors:
 *  - the router supplies a range of IPv6 addresses
 *  - the IPv6 DatagramSockets can listen to multiple ports
 *  - the IPv6 DatagramSockets could receive from multiple ports
 *
 * Incoming traffic is mapped based on an InetSocketAddress; if an exact
 * match is not available, then the zero address is tried instead.
 *
 * The sender information is stored in a Datagrampacket's SocketAddress.
 */
public class ConnectionPool {
	protected final static byte serveripbytes[] = { (byte) 145, (byte) 136, (byte) 0, (byte) 1 };
	protected final static int serverport = 25790;
	protected InetSocketAddress default_server;
	protected Hashtable<InetSocketAddress,DatagramSocket> clients;
	protected Hashtable<InetSocketAddress,ServerNode> servers;
	protected Hashtable<Inet6Address,InetSocketAddress> addressmap;


	/** The connection pool is normally a shared resource,
	 * although private instances are certainly possible.
	 */
	private static ConnectionPool pool;

	/** Create the shared connection pool when loading this class.
	 */
	static {
		try {
			pool = new ConnectionPool ();
		} catch (SocketException se) {
			throw new RuntimeException ("Failed to create initial default ConnectionPool");
		}
	}

	/** Return the connection pool intended to be shared.
	 */
	public static ConnectionPool getSharedConnectionPool () {
		return pool;
	}


	/** Start using a server, possibly introducing it.
	 * Return the ServerNode that is herewith opened.
	 */
	public ServerNode openServer (InetSocketAddress isa)
	throws UnknownHostException, SocketException {
		if (!(isa.getAddress () instanceof Inet4Address)) {
			throw new UnknownHostException ("openServer() must use an IPv4 address");
		}
		synchronized (servers) {
			ServerNode srv = servers.get (isa);
			if (srv == null) {
				srv = new ServerNode (isa);
				servers.put (isa, srv);
				srv.useMore ();
				addressmap.put (srv.getShared6bed4Address (), isa);  //TODO:BOOTSTRAP LOCKUP -- NO SHARED ADDRESS UNTIL MAINTAINER STARTS
			} else {
				srv.useMore ();
			}
			return srv;
		}
	}

	/** Stop using a server, possibly removing it.
	 */
	public void closeServer (InetSocketAddress isa)
	throws UnknownHostException {
		if (!(isa.getAddress () instanceof Inet4Address)) {
			throw new UnknownHostException ("closeServer() must use an IPv4 address");
		}
		synchronized (servers) {
			ServerNode srv = servers.get (isa);
			if (srv == null) {
				throw new UnknownHostException ("Cannot close a new server");
			}
			if (srv.useLess ()) {
				servers.remove (isa);
				addressmap.remove (srv.getShared6bed4Address ());
			}
		}
	}

	/** Return the default 6bed4 tunnel server.
	 */
	public InetSocketAddress getDefaultServer () {
		return default_server;
	}

	/** Return the ServerNode for the default 6bed4 tunnel server.
	 */
	public ServerNode getDefaultServerNode () {
		return servers.get (default_server);
	}

	/** Return the ServerNode for a given InetSocketAddress,
	 * holding the server's IPv4 address and UDP port.
	 * Returns null if not found.
	 * TODO: WHAT IS THE PURPOSE HERE?!?
	 */
	public ServerNode getServerNode (InetSocketAddress isa) {
		synchronized (servers) {
			return servers.get (isa);
		}
	}

	/** Returns the ServerNode for a given InetAddress, which
	 * is then assumed to match an Inet6Address in the
	 * hash tables.
	 * Returns null if not found.
	 */
	public ServerNode getServerNode (InetAddress ia) {
		InetSocketAddress isa = addressmap.get (ia);
		if (isa == null) {
			return null;
		}
		return servers.get (isa);
	}

	/** Change the server that counts as the default tunnel server
	 * for future connection attempts.  Existing connections are not
	 * influenced.
	 */
	public void setDefaultServer (InetSocketAddress isa)
	throws UnknownHostException, SocketException {
		if (!(isa.getAddress () instanceof Inet4Address)) {
			throw new UnknownHostException ("setDefaultServer() must use an IPv4 address");
		}
		try {
			synchronized (servers) {
				closeServer (default_server);
				default_server = isa;
				openServer (default_server);
			}
		} catch (UnknownHostException uhe) {
			throw new RuntimeException ("UseCount error for default 6bed4 tunnel server");
		}
	}

	/** Construct a ServerPool with nothing but the default server.
	 * There are no clients yet, of course.
	 */
	public ConnectionPool ()
	throws SocketException {
		clients = new Hashtable<InetSocketAddress,DatagramSocket> ();
		servers = new Hashtable<InetSocketAddress,ServerNode         > ();
		addressmap = new Hashtable<Inet6Address,InetSocketAddress    > ();
		try {
			default_server = new InetSocketAddress (InetAddress.getByAddress (serveripbytes), serverport);
		} catch (UnknownHostException uhe) {
			throw new RuntimeException ("Failed to parse IPv4 address of 6bed4 default server");
		}
		try {
			openServer (default_server);
		} catch (UnknownHostException uhe) {
			throw new RuntimeException ("Failed to initialize default 6bed4 tunnel server");
		}
	}

}

