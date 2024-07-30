import core.NetworkSniffer

fun main(args: Array<String>) {
  val networkSniffer = NetworkSniffer()
  networkSniffer.captureAll()

  val packetsToQuery = ArrayList<String>()
  while (true) {
    val input = readln()
    if (input == "stop") {
      networkSniffer.stopCapture()
      break
    }
    packetsToQuery.add(input)
  }

  val resultPackets = networkSniffer.query(packetsToQuery.joinToString(","))
  println(resultPackets)

}

