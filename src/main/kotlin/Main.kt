import mu.KLogger
import mu.KotlinLogging
import org.pcap4j.core.PacketListener
import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.Packet
import org.pcap4j.packet.UdpPacket
import java.net.InetAddress

fun main(args: Array<String>) {
    val packetRegistry = ArrayList<Packet>()

    val capturingTask = CapturingTask(packetRegistry)
    val capturingThread = Thread(capturingTask)
    capturingThread.start()

    println("Its non-blocking")
    Thread.sleep(250)
    capturingTask.stopCapturing()
    println(capturingThread.isAlive)
    val udpPackets = packetRegistry.mapNotNull { it.get(UdpPacket::class.java) }
    println(udpPackets)
}

class CapturingTask (private val packetRegistry: MutableList<Packet>) : Runnable {
    private val pcapHandle: PcapHandle
    private val logger: KLogger = KotlinLogging.logger {}

    init {
        val address = InetAddress.getByName("192.168.38.194")
        val networkInterface = Pcaps.getDevByAddress(address)
        val snapLen = 65536
        this.pcapHandle = networkInterface.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)
    }

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
