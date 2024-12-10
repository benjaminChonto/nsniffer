package core

import org.pcap4j.packet.ArpPacket
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.Packet
import org.pcap4j.packet.TcpPacket
import org.pcap4j.packet.UdpPacket
import org.pcap4j.util.MacAddress
import java.net.InetAddress

interface PacketSummary {
  fun getHeader(): List<String>

  fun getRow(): List<String>
}

fun Packet.summary(ip: IpPacket?): PacketSummary =
    when (this) {
      is TcpPacket -> this.summary(ip)
      is UdpPacket -> this.summary(ip)
      is DnsPacket -> this.summary(ip)
      is ArpPacket -> this.summary(ip)
      else -> throw NotImplementedError("Packet class does not have a summary")
    }

fun TcpPacket.summary(ip: IpPacket?): TcpPacketSummary =
    TcpPacketSummary(
        ip?.header?.srcAddr,
        ip?.header?.dstAddr,
        this.header.srcPort.valueAsString(),
        this.header.dstPort.valueAsString(),
        this.header.ack)

fun UdpPacket.summary(ip: IpPacket?): UdpPacketSummary =
    UdpPacketSummary(
        ip?.header?.srcAddr,
        ip?.header?.dstAddr,
        this.header.srcPort.valueAsString(),
        this.header.dstPort.valueAsString(),
        this.header.length.toInt(),
        this.header.checksum.toInt())

fun DnsPacket.summary(ip: IpPacket?): DnsPacketSummary =
    DnsPacketSummary(
        ip?.header?.srcAddr,
        ip?.header?.dstAddr,
        this.header.questions.map { it.qName }.joinToString("\n"),
        this.header.answers.map { it.rData }.joinToString("\n"),
    )

fun ArpPacket.summary(ip: IpPacket?): ArpSummary =
    ArpSummary(
        ip?.header?.srcAddr,
        ip?.header?.dstAddr,
        this.header.srcHardwareAddr,
        this.header.dstHardwareAddr,
        this.header.srcProtocolAddr,
        this.header.dstProtocolAddr)

data class TcpPacketSummary(
    val srcAddress: InetAddress?,
    val dstAddress: InetAddress?,
    val srcPort: String,
    val dstPort: String,
    val ack: Boolean
) : PacketSummary {
  override fun getHeader(): List<String> {
    return listOf("src address", "dst address", "src port", "dst port", "ack")
  }

  override fun getRow(): List<String> {
    return listOf(srcAddress.toString(), dstAddress.toString(), srcPort, dstPort, ack.toString())
  }
}

data class UdpPacketSummary(
    val srcAddress: InetAddress?,
    val dstAddress: InetAddress?,
    val srcPort: String,
    val dstPort: String,
    val length: Int,
    val checksum: Int
) : PacketSummary {
  override fun getHeader(): List<String> {
    return listOf("src address", "dst address", "src port", "dst port", "length", "checksum")
  }

  override fun getRow(): List<String> {
    return listOf(
        srcAddress.toString(),
        dstAddress.toString(),
        srcPort,
        dstPort,
        length.toString(),
        checksum.toString())
  }
}

data class DnsPacketSummary(
    val srcAddress: InetAddress?,
    val dstAddress: InetAddress?,
    val questions: String,
    val answers: String
) : PacketSummary {
  override fun getHeader(): List<String> {
    return listOf("src address", "dst address", "questions", "answers")
  }

  override fun getRow(): List<String> {
    return listOf(srcAddress.toString(), dstAddress.toString(), questions, answers)
  }
}

data class ArpSummary(
    val srcAddress: InetAddress?,
    val dstAddress: InetAddress?,
    val srcHardwareAddress: MacAddress,
    val dstHardwareAddress: MacAddress,
    val srcProtocolAddress: InetAddress,
    val dstProtocolAddress: InetAddress
) : PacketSummary {
  override fun getHeader(): List<String> {
    return listOf(
        "src address",
        "dst address",
        "src hardware address",
        "dst hardware address",
        "src protocol address",
        "dst protocol address")
  }

  override fun getRow(): List<String> {
    return listOf(
        srcAddress.toString(),
        dstAddress.toString(),
        srcHardwareAddress.toString(),
        dstHardwareAddress.toString(),
        srcProtocolAddress.toString(),
        dstProtocolAddress.toString())
  }
}
