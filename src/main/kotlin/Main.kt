import core.CapturingTask
import org.pcap4j.packet.Packet

fun main(args: Array<String>) {
  val packetRegistry = ArrayList<Packet>()

  val capturingTask = CapturingTask(packetRegistry)
  //    val capturingThread = Thread(capturingTask)
  //    capturingThread.start()
  //
  //    println("Its non-blocking")
  //    Thread.sleep(250)
  //    capturingTask.stopCapturing()
  //    println(capturingThread.isAlive)
  //    val udpPackets = packetRegistry.mapNotNull { it.get(UdpPacket::class.java) }
  //    println(udpPackets)
}
