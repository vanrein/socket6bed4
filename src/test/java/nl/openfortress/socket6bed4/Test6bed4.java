/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.openfortress.socket6bed4;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Test;
/**
 *
 * @author hfman
 */
public class Test6bed4 {
    DatagramSocket dgs;

    public Test6bed4() {
        try {
            dgs = new DatagramSocket();
            InetAddress localhost = Inet6bed4Address.getLocalHost();
            System.out.println(localhost);
        } catch (SocketException ex) {
            Logger.getLogger(Test6bed4.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnknownHostException ex) {
            Logger.getLogger(Test6bed4.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testSend() throws Exception {
        String msg = "Hello, Java!";
        byte buf[] = msg.getBytes(Charset.forName("UTF-8"));
        try {
            DatagramPacket packet =
                    new DatagramPacket(buf, buf.length, InetAddress.getByName("2a01:4f8:1c1c:1a30::1"), 12345);
            dgs.send(packet);
        } catch (UnknownHostException ex) {
            Logger.getLogger(Test6bed4.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Test6bed4.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
