<img src="./assets/icewall-cover.png"/>
<h3 align="center"> A fireless firewall written for Linux systems that filters incoming and outgoing network packets based on customized rules</h3>
<img src="./assets/icewall-logo.png"/>

## Features list

<ul>
    <li>filter by single IP address</li>
    <li>filter by subnet - using CIDR notation</li>
    <li>filter by single port</li>
    <li>filter by port range</li>
    <li>filter by transport layer protocol</li>
</ul>

## Table of contents
[Technical information](#technical-information)

[Building the icewall](#building-the-icewall)

- [Dependencies](#dependencies)

- [Downloading the source code](#downloading-the-source-code)

- [Setting up the CMake build system](#setting-up-the-cmake-build-system)

- [Compiling the source code](#compiling-the-source-code)

[Launching the icewall](#launching-the-icewall)

[Defining rules](#defining-rules)

- [Drop](#drop)

- [Accept](#accept)

- [Default policy](#default-policy)

- [Rule modifiers](#rule-modifiers)

[Rules management](#rules-management)

- [Listing rules](#listing-rules)

- [Removing rules](#removing-rules)

## Technical information
The icewall is a security application written in C programming language. The core of this application is a binary that runs on kernel mode, analysing incoming and outgoing network packets and testing them against  defined rules.

The software is divided into two binaries, the kernel module and a controller, that acts as a front-end to create rules, list them and so on.

## Building the icewall
The icewall build process is relatively easy, a single script can make everything for you. Although easily done, a few steps must be performed before compiling the source code.

### Dependencies
The kernel module build process requires the package `linux-headers` to be installed on your machine. The installation process of this package depends on what distribution you are pretending to run the icewall.

```sh
# Arch Linux based distributions
sudo pacman -S linux-headers

# Debian based distributions
sudo apt install linux-headers-$(uname -r)

# Search for the package on your distro...
```

### Downloading the source code
If you have Git installed on your machine, the following command should do the trick:
```sh
git clone https://github.com/Romulo-Moraes/icewall.git
```

If you don't, you can download the zip file directly on the `code` button above the source tree.

### Setting up the CMake build system
The icewall project uses the CMake exclusively to build the controller program. If you don't have it installed on your machine, search on web how to install it on your distribution.

```sh
# Arch Linux based distributions
sudo pacman -S cmake

# Debian based distribution
sudo apt install cmake
```


Assuming that you are in the project's root directory, the following set of commands should do the trick:
```sh
cd controller/build
cmake ..
cd ../..
```

### Compiling the source code
To make the overall compilation process easier, the project have a build.sh file on its root directory. After correctly setting up the CMake and installing all dependencies, running that script should build both programs and output them inside the `out` directory.
```sh
sh build.sh
```

## Launching the icewall
After running the build.sh script, the `out` directory should have two files.

<ul>
    <li>icewall.ko - the firewall itself</li>
    <li>wallctl - the icewall controller</li>
</ul>

To launch the icewall on you machine, you must load it on your kernel using the following command:
```sh
sudo insmod icewall.ko
```
After that the firewall is running and ready to receive new rules.

## Defining rules
Rules are parameters used to test network packets and verify if they must be dropped once they hit the icewall or allowed to move forward to their destination.

### Drop
The drop rule tells the icewall to drop any packet that match its filter. The syntax of this rule is the following:
```txt
drop <incoming/outgoing> <[address]:[port]:[protocol]>
```
Description: drops the incoming or outgoing packets that match the filter.
             [ address | port | protocol ] are optional, but at least one is required.

example:
```txt
wallctl drop incoming 192.168.1.107:8080
```

### Accept
The accept rule tells the icewall to allow the passage of any packet that match its filter. The syntax of this rule is the following:
```txt
accept <incoming/outgoing> <[address]:[port]:[protocol]>
```
Description: accepts the incoming or outgoing packets that match the filter.
             [ address | port | protocol ] are optional, but at least one is required.

example:
```txt
wallctl accept outgoing 95.217.163.246:udp
```

### Default policy
A policy is a value used by the icewall as a default action when a packet didn't match any other rule. A strategic use of policies can simplify the implementation of the firewall itself.
```txt
default <incoming/outgoing> policy <accept/drop>
```
Description: sets the default policy of incoming or outgoing packets to accept or drop.


example:
```txt
# Only allow loopback packets
wallctl default incoming policy drop
wallctl accept incoming 127.0.0.1
```

### Rule modifiers
#### Subnets
You can specify a subnet using the CIDR notation.
```txt
drop incoming 192.168.1.0/24
```
The rule above drops incoming packets from addresses 192.168.1.0 to 192.168.1.255

#### Port ranges
Ports can also be specified by ranges.
```txt
accept outgoing 8080-8085
```
The above rule accepts outgoing packets that target ports from 8080 to 8085 (inclusive).

## Rules management
### Listing rules
You can list the active rules and also check the default policy by running the following command:
```txt
wallctl list <incoming/outgoing>
```

### Removing rules
You can also remove a rule using the ID shown by the list command:
```txt
wallctl rm <incoming/outgoing> <id>
```
