import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.mordant.rendering.BorderType
import com.github.ajalt.mordant.rendering.OverflowWrap
import com.github.ajalt.mordant.rendering.TextColors
import com.github.ajalt.mordant.rendering.TextStyles
import com.github.ajalt.mordant.table.table
import com.github.ajalt.mordant.terminal.Terminal
import core.NetworkSniffer
import core.PacketSummary
import mu.KLogger
import mu.KotlinLogging

private val logger: KLogger = KotlinLogging.logger {}

class Capture : CliktCommand() {
  private val queries: String by option(help = """
          Type of packets to capture separated by a comma e.g. tcp,udp
  """.trimIndent()).default("tcp,udp,dns,arp")

  override fun run() {
    val networkSniffer = NetworkSniffer()
    networkSniffer.captureAll()
    logger.info { "Capturing has started, press <enter> to stop" }
    readln()
    networkSniffer.stopCapture()
    printPackets(networkSniffer.query(queries))
  }

  private fun printPackets(packetMap: Map<String, List<PacketSummary>>) {
    val t = Terminal()
    t.updateSize()
    val style = (TextColors.brightMagenta + TextStyles.bold)
    packetMap.filter { it.value.isNotEmpty() }
        .keys.forEach {
          t.println(
              table {
                captionTop(TextColors.blue("${style(it)} packets (${packetMap[it]?.size})"))
                borderType = BorderType.SQUARE
                borderStyle = TextColors.brightBlue
                val headerList = packetMap[it]?.first()?.getHeader()!!
                header {
                  row(*headerList.toTypedArray()) { overflowWrap = OverflowWrap.BREAK_WORD }
                }
                body {
                  packetMap[it]?.forEach { summary ->
                    row(*summary.getRow().toTypedArray()) { overflowWrap = OverflowWrap.BREAK_WORD }
                  }
                }
              })
        }
    t.println("\n")
  }
}

fun main(args: Array<String>) = Capture().main(args)
