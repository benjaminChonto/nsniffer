# Network Sniffer
This application can record network traffic using the [pcap4j](https://github.com/kaitoy/pcap4j) library.
This library requires either [libpcap](https://www.tcpdump.org/) (installed by default on modern Unix systems) or [Npcap](https://npcap.com/) for Windows to be installed on the system.

Executing capturing is done through a command line interface. To see the possible arguments run the application with the -h flag:
```
Usage: capture [<options>]

Options:
--queries=<text>  Type of packets to capture separated by a comma e.g.
tcp,udp
--delay=<int>     Delay in seconds before start of capturing
--interval=<int>  How many seconds should be captured
-h, --help        Show this message and exit
```

Without any arguments, all possible packets (tcp,udp,dns,arp) will be summarized and printed after the execution is stopped.
Without setting an interval, the application is stopped by pressing *enter*.

To make sure that the output tables are fully visible it is advised to run the program directly from the terminal.
To do this run the following:
```commandLine
./gradlew build
cd build/distributions
tar -xzf nsniffer-1.0-SNAPSHOT.tar
cd nsniffer-1.0-SNAPSHOT/bin
./nsniffer
```

Example call with 2 seconds delay, 5 seconds of recording and collecting udp and dns packages:
```commandLine
./nsniffer --delay=2 --interval=5 --queries=udp,dns
```
