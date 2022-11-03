# kissTUN

---
## Description

a simple KISS/AX.25 implementation with TAP interface

the detail of KISS protocol: see [https://www.ax25.net/kiss.aspx](https://www.ax25.net/kiss.aspx)

## Usage

```
# kisstun
usage: kisstun -s [serial speed] -l [serial device] -t [tun device] -xs[callsign]
#
```
Note: no space required between `-xs` and `callsign`.


### Example

#### set up KISS/AX.25 port on OpenBSD

```
# ifconfig tap0 create
# ifconfig tap0 inet 192.168.200.1/24
# ifconfig tap0 mtu 255 up
# kisstun -s 9600 -l /dev/tty00 -t /dev/tap0 -xsN0CALL-2 &
```
You can use `kisstun -p 8001 -l 192.168.100.1 -t /dev/tap0 -xsN0CALL-2 &` to use with [Dire Wolf](https://github.com/wb2osz/direwolf) instead of TNC.

#### set up KISS/AX.25 port on Linux with kisstun

```
# ip tuntap add mode tap dev tap0
# ip addr add 192.168.200.2/24 dev tap0
# ip link set up mtu 255 dev tap0
# kisstun -s 9600 -l /dev/ttyS1 -t tap0 -xsN0CALL-8 &
```

#### set up KISS/AX.25 port on Linux with kissattach (standard tool)

Prepare /etc/ax25/axports, use "1" for port name in this example.

```
# /sbin/kissattach /dev/ttyS1 1
# /sbin/kissparms -c 1 -p 1
# ip addr add 192.168.200.2/24 dev ax0
```

## Options

Note: `-x` options do not require space between options and their argument.

<dl>
 <dt><code>-s &lt;speed&gt;</code>
 <dd>Work with serial port, <code>&lt;speed&gt;</code> bps. Suitable for hardware TNC.
 <dt><code>-p &lt;port&gt;</code> or <code>-P &lt;port&gt;</code>
 <dd>Work with TCP/IP, suitable for software TNC (e.g. Dire Wolf). <code>-p</code> works as a client, port number to connect. <code>-P</code> works as a server, port number for accept (be careful for security).
 <dt><code>-l &lt;serial device&gt;</code> or <code>-l &lt;IP address&gt;</code>
 <dd>Target serial device (i.e. <code>/dev/ttyS1</code>) when use with <code>-s</code> option. Accept/connect IP address (i.e. <code>0.0.0.0</code>) when use with <code>-p</code> or <code>-P</code> option. 
 <dt><code>-t &lt;TAP device&gt;</code>
 <dd>TAP device name, i.e. <code>/dev/tap0</code> for *BSD users. Linux uses the name declared at <code>ip tuntap add mode tap dev</code>.
 <dt><code>-f</code>
 <dd>(serial port only) Enable RTS/CTS hardware handshaking, default disable.
 <dt><code>-xs&lt;mycall&gt;</code>
 <dd>Operator callsign, mandatory.
 <dt><code>-xb&lt;broadcastcall&gt;</code>
 <dd>Callsign for broadcast packet, default <code>-xbQST</code>.
 <dt><code>-xo&lt;octet&gt;</code>
 <dd>Emulated unicast MAC address for 0th octet, default <code>-xo0xfe</code>.
 <dt><code>-xn</code>
 <dd>Accept source&gt;source packet (it is observed when ARP is disabled on Linux), default reject. 
 <dt><code>-xq&lt;loglevel&gt;</code>
 <dd>Set log level (<code>0</code> is quiet), default <code>-xq255</code>.
 <dt><code>-xma</code>
 <dd>Enable multicast packet, default disable.
 <dt><code>-xmx</code>
 <dd>Enable multicast address encoder, use with <code>-xma</code>. Default disable. If the encoder is enabled, destination 33:33:xx:xx:xx:xx packets will be converted to callsign started with <code>,P</code> to <code>,_</code> and vice versa. Destination 01:00:5e:xx:xx:xx packets will be <code>`%X</code> to <code>`%[</code>. Other multicast packets or the encoder is disabled, multicast packets are sent as broadcast. 
 <dt><code>-xmi</code>
 <dd>Enable all multicast IP address transaction. Default disable; multicast IP addresses (224.0.0.0/4 and FF00::/8) except FF02:0:0:0:0:1:FF00/104 (Solicited-Node Address) are blocked.
 <dt><code>-x6</code>
 <dd>Enable IPv6 transaction, default disable. Due to NDP (Neighbor Discovery Protocol) uses IPv6 multicast, using <code>-xma</code> option is recommended.
</dl>

## Limitation

No plan to support digipeater.

## License

MIT License

## References

[AX.25 Transport Layer Drivers for TCP/IP](https://web.tapr.org/meetings/DCC_1995/DCC1995-AX.25TransportDrivers4TCP-IP-KB2ICI-N2KBG.pdf) (KB2ICI, N2KBG 1995)

## Acknowledgement

Thanks to [SAGAMI-NET](https://www.sagami-net.jp/) members that bring me to AX.25 network world.
