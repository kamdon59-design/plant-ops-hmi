# EtherNet/IP Device Scanner

A small desktop app that finds Allen-Bradley PLCs, PanelView HMIs, drives, I/O adapters, and any other
EtherNet/IP (CIP) device on the network your laptop is plugged into. For each device it shows:

| Column | Where it comes from |
|---|---|
| **IP address** | Source of the List Identity reply |
| **MAC address** | CIP Ethernet Link Object (class 0xF6, attr 3) over TCP. If that fails, the OS ARP table is used. The tag next to the MAC shows which one was used. |
| **Part number** | Catalog number taken from the device's product name (e.g. `1769-L33ER/A`) |
| **Product name / code** | CIP Identity Object |
| **Firmware** | Identity revision `major.minor` (e.g. `33.011`) |
| **Serial #, device type, vendor** | CIP Identity Object |

When you plug in an Ethernet cable, the scan starts on its own. The app checks your network adapters
every 2 seconds and scans any adapter that gets a new IP address.

The app has light and dark themes. The **System / Light / Dark** switch in the header controls it and is remembered between runs. **System** follows the Windows setting.

## Install

1. **Install Npcap** (free) from https://npcap.com/#download, using the default options. The app uses it to
   find devices on **any subnet**, so you don't need to know a device's IP or change your laptop's IP first.
   Without Npcap, the app still works but only finds devices in your laptop's own subnet. It shows a
   **Get Npcap** button in that case.
2. Run the app:

```
cd ethernetip-scanner
npm install
npm start
```

To build a Windows installer, run `npm run build`. The installer is written to `dist/`. You don't need
Visual Studio or any other compiler: the packet-capture binding (`koffi`) ships prebuilt.

## Finding devices when you don't know their IP

Your laptop can be on `192.168.1.x` and the device on `172.16.30.x`, or the laptop can have no IP at all
(`169.254.x.x`). The app still finds the device, using raw Ethernet frames through Npcap:

1. **It listens.** Capture starts when the app opens, on every wired adapter. When you plug in the cable,
   most EtherNet/IP devices announce their own IP address on the wire (address conflict detection / ARP).
   The app picks that up and identifies the device straight away.
2. **It probes every private subnet.** It sends an identity request to each subnet in `192.168.0.0/16` and
   `172.16.0.0/12` (and `10.0.0.0/8` if you tick **Include 10.x.x.x**). Each request appears to come from an
   address inside that subnet and goes to that subnet's broadcast address. A device on that subnet replies,
   and its reply reveals its IP. Devices on other subnets ignore the request, so the search doesn't add load
   to the plant network. It takes about 3 seconds, or about 20 seconds with 10.x.
3. **It reads the identity.** For each IP it finds, the app picks a free address in the device's subnet. It
   first checks that nobody owns that address. It then reads the identity from that address and captures the
   reply directly. **Your laptop's IP settings are never changed.** The app only answers network address
   lookups (ARP) for the device it is talking to, so other devices' address tables aren't touched.

Devices found this way get an **Other subnet** badge that shows a free laptop IP in their subnet, e.g.
`use laptop IP 172.16.30.239`. To connect with RSLinx, Studio 5000, FactoryTalk or a web browser, set your
Ethernet adapter to that address with mask `255.255.255.0`.

## How the normal scan works

1. It sends an EtherNet/IP **List Identity** (encapsulation command `0x63`) over UDP port **44818** to the
   adapter's subnet broadcast address and to `255.255.255.255`.
2. When **Sweep whole subnet** is on, it also sends List Identity directly to every host in the laptop's own
   subnet (subnets up to /22). This finds devices that ignore broadcasts.
3. **Extra IPs** probes specific addresses directly, such as a device behind a router.
4. For each device that answers, it opens a short TCP session (RegisterSession → Get_Attribute_Single) to
   read the MAC address.

The app never writes to devices. It only sends read-only identity and attribute requests.

## Troubleshooting

- **No devices found.** Check the link lights. Then unplug and re-plug the cable while the app is open:
  most devices announce their IP when the link comes up.
- **A device with a subnet mask narrower than /24 (e.g. `255.255.255.128`), no gateway, and no link-up
  announcement can be missed.** This is uncommon on plant networks. Re-plugging the cable usually reveals it.
- **"Install Npcap" banner.** Npcap isn't installed, or was installed in "admin-only" mode. In that case,
  run the app as administrator.
- **Corporate laptops.** Some endpoint-security products block packet injection. If the app finds devices
  in your own subnet but never on other subnets, that may be the reason.
- **Part number shows "—".** Some devices (PowerFlex drives, third-party devices) don't include the catalog
  number in their product name. The product name and product code are still shown.

## Testing without hardware

```
npm test                   # unit tests, incl. simulated devices on other subnets
npm run mock               # start a fake 1769-L33ER on port 44818, then npm start in another terminal
```
