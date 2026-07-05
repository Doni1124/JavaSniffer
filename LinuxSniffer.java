import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import java.util.List;

public class LinuxSniffer {

    public static void main(String[] args) {
        PcapHandle handle = null;

        try {
            // Find all network interfaces
            List<PcapNetworkInterface> allIfs = Pcaps.findAllDevs();
            if (allIfs == null || allIfs.isEmpty()) return;
            
            // Pick an active interface
            PcapNetworkInterface nif = allIfs.get(0);
            for (PcapNetworkInterface device : allIfs) {
                if (!device.getAddresses().isEmpty()) {
                    nif = device;
                    break;
                }
            }

            System.out.println("🔍 Sniffing Layers on: " + nif.getName());
            System.out.println("-------------------------------------------------------");

            // Open the interface manually (Old school try-finally style)
            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
                
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    
                    // 1. LAYER 2: DATA LINK (MAC Addresses)
                    EthernetPacket eth = packet.get(EthernetPacket.class);
                    if (eth != null) {
                        System.out.println("[L2] MAC: " + eth.getHeader().getSrcAddr() + " -> " + eth.getHeader().getDstAddr());
                    }

                    // 2. LAYER 3: NETWORK (IP Addresses)
                    if (packet.contains(IpV4Packet.class)) {
                        IpV4Packet ip = packet.get(IpV4Packet.class);
                        System.out.println("[L3] IPv4: " + ip.getHeader().getSrcAddr() + " -> " + ip.getHeader().getDstAddr());
                    }

                    // 3. LAYER 4: TRANSPORT (TCP/UDP Ports)
                    int srcPort = 0, dstPort = 0;
                    String transportProto = "";

                    if (packet.contains(TcpPacket.class)) {
                        TcpPacket tcp = packet.get(TcpPacket.class);
                        srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                        dstPort = tcp.getHeader().getDstPort().valueAsInt();
                        transportProto = "TCP";
                        System.out.println("[L4] Transport: TCP | Ports: " + srcPort + " -> " + dstPort);
                    } else if (packet.contains(UdpPacket.class)) {
                        UdpPacket udp = packet.get(UdpPacket.class);
                        srcPort = udp.getHeader().getSrcPort().valueAsInt();
                        dstPort = udp.getHeader().getDstPort().valueAsInt();
                        transportProto = "UDP";
                        System.out.println("[L4] Transport: UDP | Ports: " + srcPort + " -> " + dstPort);
                    }

                    // 4. LAYER 7: APPLICATION (Protocol Identification)
                    if (!transportProto.isEmpty()) {
                        checkApplication(dstPort, srcPort);
                    }

                    System.out.println("-------------------------------------------------------");
                }
            };

            // Start the capture loop
            handle.loop(-1, listener);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        }
    }

    private static void checkApplication(int dstPort, int srcPort) {
        // Simple Port-to-App Mapping
        if (dstPort == 80 || srcPort == 80) System.out.println("[L7] App: HTTP (Web)");
        else if (dstPort == 443 || srcPort == 443) System.out.println("[L7] App: HTTPS (Secure Web)");
        else if (dstPort == 53 || srcPort == 53) System.out.println("[L7] App: DNS (Domain Name System)");
        else if (dstPort == 22 || srcPort == 22) System.out.println("[L7] App: SSH (Remote Access)");
        else if (dstPort == 23 || srcPort == 23) System.out.println("[L7] App: TELNET (Unsecure Access)");
        else System.out.println("[L7] App: Unknown / Other Service");
    }
}
