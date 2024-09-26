package core

import org.pcap4j.packet.ArpPacket
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.Packet
import org.pcap4j.packet.TcpPacket
import org.pcap4j.packet.UdpPacket


class PacketRepository {

    private val packets: MutableList<Packet> = ArrayList()

    fun add(packet: Packet) {
        packets.add(packet)
    }

    fun clear() {
        packets.clear()
    }

    fun merge(repositories: List<PacketRepository>) {
        repositories.forEach{ packets.addAll(it.packets) }
    }

    fun query(query: String): List<Packet> {
        val queryMap = mapOf(
            "udp" to UdpPacket::class.java,
            "tcp" to TcpPacket::class.java,
            "dns" to DnsPacket::class.java,
            "arp" to ArpPacket::class.java
        )
        // for now let's say that query can only be a network protocol
        return packets.mapNotNull { it.get(queryMap[query]) }
    }

}