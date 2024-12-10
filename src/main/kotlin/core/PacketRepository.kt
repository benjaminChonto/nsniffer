package core

import org.pcap4j.packet.ArpPacket
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.Packet
import org.pcap4j.packet.TcpPacket
import org.pcap4j.packet.UdpPacket

class PacketRepository(private val packets: MutableList<Packet> = ArrayList()) {

  fun add(packet: Packet) {
    packets.add(packet)
  }

  fun clear() {
    packets.clear()
  }

  fun merge(repositories: List<PacketRepository>) {
    repositories.forEach { packets.addAll(it.packets) }
  }

  fun query(query: String): List<PacketSummary> {
    val queryMap =
        mapOf(
            "udp" to UdpPacket::class.java,
            "tcp" to TcpPacket::class.java,
            "dns" to DnsPacket::class.java,
            "arp" to ArpPacket::class.java)

    return packets.mapNotNull {
      val ip: IpPacket? = it.get(IpPacket::class.java)
      it.get(queryMap[query])?.summary(ip)
    }
  }
}
