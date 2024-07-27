package core

import mu.KLogger
import mu.KotlinLogging
import org.pcap4j.core.PacketListener
import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.Packet

class CapturingHandle(private var packetRegistry: Map<String, MutableList<Packet>>) {
  private val pcapHandles: Map<String, PcapHandle>
  private val logger: KLogger = KotlinLogging.logger {}
  private val snapLen = 65536

  init {
    // TODO: class for mapping from interface name to (handle, registry, capturingTask)
    val interfaces = Pcaps.findAllDevs().filter { it.isUp }
    logger.info { "Found ${interfaces.size} open interfaces: ${interfaces.map { it.name } }" }
    pcapHandles =
        interfaces.associate {
          it.name to it.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)
        }
    packetRegistry = interfaces.associate { it.name to ArrayList<Packet>() }
    interfaces.forEach {
      // TODO: collect capturing tasks
      CapturingTask(pcapHandles.getValue(it.name), packetRegistry.getValue(it.name))
    }
  }

  class CapturingTask(
      private val pcapHandle: PcapHandle,
      private val packetRegistry: MutableList<Packet>
  ) : Runnable {
    private val logger = KotlinLogging.logger {}

    fun stopCapturing() {
      pcapHandle.breakLoop()
    }

    override fun run() {
      try {
        pcapHandle.loop(-1, PacketListener { packetRegistry.add(it) })
      } catch (iex: InterruptedException) {
        logger.info { "Packet capturing has been interrupted, closing pcap handler..." }
      }
      pcapHandle.close()
    }
  }
}
