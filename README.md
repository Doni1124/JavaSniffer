# # Linux Network Packet Sniffer

A lightweight Java application that captures and analyzes real-time network traffic across multiple layers of the OSI model. Built using **Pcap4J**, it automatically binds to an active interface and dissects live frame headers into human-readable data logs.

---

## ## Project Architecture

The project is structured to manage external dependencies manually without requiring an external build automation engine (like Maven or Gradle).

```text
.
├── LinuxSniffer.java
└── libs/
    ├── jna-5.13.0.jar
    ├── pcap4j-core-1.8.2.jar
    ├── pcap4j-packetfactory-static-1.8.2.jar
    └── slf4j-api-1.7.30.jar

```

---

## ## Prerequisites

Before compiling and executing the program, your Linux operating system must satisfy the following requirements:

1. **Java Development Kit (JDK):** Version 8 or higher must be installed.
2. **Native Capture Library (`libpcap`):** Pcap4J requires the low-level C subsystem binary components to interact directly with network interface drivers.

### ### Installation Commands

Run the corresponding installation string depending on your package manager:

* **Ubuntu / Debian Derivatives:**
```bash
sudo apt-get update && sudo apt-get install -y libpcap-dev

```


* **RHEL / CentOS / Fedora:**
```bash
sudo dnf install -y libpcap-devel

```



---

## ## Step-by-Step Instructions

Open your Linux terminal inside the project root directory (where `LinuxSniffer.java` resides) and run the following execution sequence:

### ### Step 1: Compile the Source Code

You must manually instruct the Java compiler (`javac`) to append the dependency tracking path (`-cp`) pointing to your nested `libs` directory.

```bash
javac -cp "libs/*" LinuxSniffer.java

```

### ### Step 2: Grant Capabilities / Execute with Root

Raw socket manipulation and entering network interface hardware cards into **Promiscuous Mode** requires administrator privileges on Linux systems.

Execute the compiled class with **`sudo`** while keeping the library classpath flag intact:

```bash
sudo java -cp ".:libs/*" LinuxSniffer

```

> 💡 **Note:** The `.:` prefix explicitly ensures that Java looks inside your current working directory for your compiled `LinuxSniffer.class` bytecode alongside the dependencies tucked away in the `libs/` folder.

---

## ## How It Works

Upon execution, the code performs the following tasks:

* **Device Selection:** Scans your operating system for networking interfaces (`eth0`, `wlan0`, etc.) and automatically selects the first operational hardware device matching a bound valid IP address.
* **Layer 2 (Data Link Layer):** Extracts hardware Source and Destination MAC addresses via `EthernetPacket`.
* **Layer 3 (Network Layer):** Parses out the communication endpoints via `IpV4Packet`.
* **Layer 4 (Transport Layer):** Filters protocols into `TcpPacket` or `UdpPacket` streams to track source and destination application ports.
* **Layer 7 (Application Layer):** Determines the likely underlying user-space service (such as HTTP, HTTPS, DNS, or SSH) based on standardized IANA port match structures.
