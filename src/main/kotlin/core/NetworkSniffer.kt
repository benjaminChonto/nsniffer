package core

import org.pcap4j.packet.Packet

class NetworkSniffer {

  init {
    val packetRegistry = ArrayList<Packet>() // TODO: create separate class
    val capturingTask = CapturingTask(packetRegistry)
  }
}
