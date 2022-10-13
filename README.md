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

## Limitation

No plan to support digipeater.

## License

MIT License

## References

[AX.25 Transport Layer Drivers for TCP/IP](https://web.tapr.org/meetings/DCC_1995/DCC1995-AX.25TransportDrivers4TCP-IP-KB2ICI-N2KBG.pdf) (KB2ICI, N2KBG 1995)

## Acknowledgement

Thanks to [SAGAMI-NET](https://www.sagami-net.jp/) members that bring me to AX.25 network world.
