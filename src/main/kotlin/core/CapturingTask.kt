package core

import mu.KotlinLogging
import org.pcap4j.core.PacketListener
import org.pcap4j.core.PcapHandle

class CapturingTask(
    val pcapHandle: PcapHandle,
    val packetRegistry: PacketRepository
) : Runnable {
  private val logger = KotlinLogging.logger {}

  fun stopCapturing() {
    pcapHandle.breakLoop()
  }

  fun clear() {
    packetRegistry.clear()
  }

  override fun run() {
    try {
      pcapHandle.loop(-1, PacketListener { packetRegistry.add(it) })
    } catch (iex: InterruptedException) {
      logger.info { "Packet capturing has been interrupted, closing pcap handler" }
      pcapHandle.close()
    }
  }
}
