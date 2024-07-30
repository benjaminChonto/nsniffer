package core

import mu.KLogger
import mu.KotlinLogging
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.Packet

class NetworkSniffer {

  private val captureTaskMap: Map<String, CapturingTask>
  private val logger: KLogger = KotlinLogging.logger {}
  private var repository: PacketRepository = PacketRepository()
  private val snapLen = 65536

  init {
    val interfaces = Pcaps.findAllDevs().filter { it.isRunning }
    logger.info { "Found ${interfaces.size} open interfaces: ${interfaces.map { it.name }}" }
    captureTaskMap = interfaces.associate {
      val pcapHandle = it.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)
      val packetRepository = PacketRepository()
      val capturingTask = CapturingTask(pcapHandle, packetRepository)
      it.name to capturingTask
    }
  }

  fun captureAll() {
    if (captureTaskMap.isEmpty()) {
      logger.debug { "Cannot capture, because no network interfaces were found" }
    }
    captureTaskMap.forEach { Thread(it.value).start() }
  }

  fun stopCapture() {
    captureTaskMap.forEach { it.value.stopCapturing() }
    repository.merge(captureTaskMap.values.map { it.packetRegistry })
    captureTaskMap.forEach { it.value.clear() }
  }

  fun query(query: String): List<Packet> {
    return query.split(",").flatMap { repository.query(it) }.toList()
  }

}
