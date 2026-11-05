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

## Run it

```
cd ethernetip-scanner
npm install
npm start
```

Build a Windows installer (it is written to `dist/`):

```
npm run build
```

## How it scans

1. It sends an EtherNet/IP **List Identity** (encapsulation command `0x63`) over UDP port **44818** to the
   adapter's subnet broadcast address and to `255.255.255.255`.
2. When **Sweep whole subnet** is on, it also sends List Identity directly to every host in the subnet
   (subnets up to /22). This finds devices that ignore broadcasts.
3. **Extra IPs** probes specific addresses directly, such as a device on a different subnet behind a router.
4. For each device that answers, it opens a short TCP session (RegisterSession → Get_Attribute_Single) to
   read the MAC address.

The app does not write anything to the devices. It only sends read-only identity and attribute requests.

## Troubleshooting

- **The adapter shows `169.254.x.x` (amber warning).** No DHCP server answered, which is normal on plant
  networks. Set a static IP on your laptop's Ethernet adapter in the same subnet as the equipment, e.g.
  `192.168.1.250 / 255.255.255.0`, then scan again.
- **No devices found.** Allow the app through Windows Firewall when it asks (UDP and TCP 44818). Make sure
  the "Ethernet" network profile isn't blocking inbound UDP replies. Also check that the cable goes to an
  Ethernet/IP port and not a DH+ or serial port.
- **Part number shows "—".** Some devices (PowerFlex drives, third-party devices) don't include the catalog
  number in their product name. The product name and product code are still shown.
- **MAC shows "not available".** The device didn't answer the CIP request, and it isn't in the ARP table
  (for example, it's behind a router).

## Testing without hardware

```
npm test                   # unit tests + loopback test against a mock device
npm run mock               # start a fake 1769-L33ER on port 44818, then npm start in another terminal
```
