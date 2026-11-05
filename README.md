# Plant Operations Console — HMI Kiosk Launcher

## Quick Start

### 1. Install dependencies
```
npm install
```

### 2. Test the app
```
npm start
```

### 3. Build the Windows installer
```
npm run build
```
The installer will be in the `dist/` folder.

---

## Default Admin Password
**admin1234**

Change it inside the app: click **⚙ Admin** → enter password → **Settings** tab.

---

## Managing Connections (without opening the app)
Edit `connections.json` in the install folder with Notepad. Each entry:
```json
{ "id": 1, "label": "My HMI", "type": "vnc", "target": "192.168.1.10" }
```
**Types:** `vnc` | `ftvp` | `url` | `app`

---

## Emergency Exit (for IT/Maintenance)
Press **Ctrl + Shift + Q** to quit the kiosk at any time.

---

## Auto-Start on Windows Boot
1. Press `Win + R`, type `shell:startup`, press Enter
2. Create a shortcut to `Plant Operations Console.exe` in that folder

## Icon
Place a 256x256 `icon.ico` file in the `assets/` folder before building.
A free converter: https://convertio.co/png-ico/

---

## EtherNet/IP Device Scanner
A separate desktop tool in [`ethernetip-scanner/`](ethernetip-scanner/README.md). It finds Allen-Bradley PLCs, HMIs, and
other EtherNet/IP devices when you plug in a cable, and lists their IP, MAC, part number, and firmware.
