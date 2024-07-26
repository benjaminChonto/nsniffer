import org.pcap4j.core.PacketListener
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.Pcaps
import java.net.InetAddress

fun main(args: Array<String>) {
    val address = InetAddress.getByName("192.168.169.194")
    val networkInterface = Pcaps.getDevByAddress(address)
    val snapLen = 65536
    val pcapHandle = networkInterface.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)

    pcapHandle.loop(2, PacketListener { println(it) })
    pcapHandle.close()
}