# libpcap-dos-monitor
[![Build Status](https://travis-ci.org/nickxla/libpcap-dos-monitor.svg?branch=master)](https://travis-ci.org/nickxla/libpcap-dos-monitor)  
This program monitors TCP SYN and DNS traffic (UDP on port 53), prints details of these packets and counts monitored packets out of total packets.    
As Denial of Service and Distributed Denial of Service consists in massive sending of these packets, this program can be used to monitor TCP SYN and DNS traffic on a network.  
This program is mainly to pratice C programming with [libpcap](http://www.tcpdump.org/) and not an enterprise-like DoS detector.

## Compilation Instructions

If libpcap is not installed, you can install it by typing:
```
apt-get install libpcap-dev
```

Compilation was made with gcc like this:
```
gcc -lpcap main.c -o monitor
```

You have to tell the program the desired network interface to listen on as the first argument.  
You can run it like this, assuming *eth0* is your network interface.
```
./monitor eth0
```

If you don't know your network interfaces you can get it with `ifconfig`.
