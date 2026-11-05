/* global scannerAPI */
const $ = (id) => document.getElementById(id);
const devices = new Map(); // ip -> device
let adapters = [];
let busy = false;

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function setStatus(msg, isErr = false) {
  $('status').textContent = msg;
  $('status').classList.toggle('err', isErr);
}

function setBusy(on) {
  busy = on;
  $('spinner').classList.toggle('on', on);
  $('btn-scan').disabled = on;
  $('btn-scan').textContent = on ? 'Scanning…' : 'Scan Now';
}

function ipKey(ip) {
  return ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);
}

function renderAdapters() {
  const wrap = $('adapters');
  wrap.innerHTML = '';
  if (!adapters.length) {
    wrap.innerHTML = '<div class="chip warn"><span class="dot"></span>No network connection — plug in an Ethernet cable</div>';
  }
  for (const a of adapters) {
    const chip = document.createElement('div');
    chip.className = 'chip' + (a.linkLocal ? ' warn' : '') + (a.virtual ? ' virt' : '');
    chip.title = `MAC ${a.mac}  ·  mask ${a.netmask}${a.virtual ? '  ·  virtual adapter (skipped)' : ''}`;
    chip.innerHTML = `<span class="dot"></span><b>${esc(a.name)}</b><span class="mono">${esc(a.address)}/${maskBits(a.netmask)}</span>`;
    wrap.appendChild(chip);
  }

  const sel = $('sel-adapter');
  const cur = sel.value;
  sel.innerHTML = '<option value="">All wired adapters</option>' +
    adapters.filter((a) => !a.virtual).map((a) => `<option value="${esc(a.name)}">${esc(a.name)} — ${esc(a.address)}</option>`).join('');
  if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;

  const ll = adapters.find((a) => a.linkLocal && !a.virtual);
  const notice = $('notice');
  if (ll) {
    notice.style.display = 'block';
    notice.innerHTML = `⚠ <b>${esc(ll.name)}</b> has a self-assigned address (${esc(ll.address)}) — there is no DHCP server on this network. ` +
      'Devices with static IPs may not answer. Give your laptop a static IP in the plant subnet ' +
      '(e.g. 192.168.1.250 / 255.255.255.0) and scan again, or enter the device IP under <b>Extra IPs</b>.';
  } else {
    notice.style.display = 'none';
  }
}

function maskBits(mask) {
  return mask.split('.').reduce((n, o) => n + (Number(o).toString(2).match(/1/g) || []).length, 0);
}

function renderDevices() {
  const list = [...devices.values()].sort((a, b) => ipKey(a.ip) - ipKey(b.ip));
  $('tbl').hidden = list.length === 0;
  $('empty').style.display = list.length ? 'none' : 'block';
  $('btn-export').disabled = list.length === 0;
  $('count').textContent = list.length ? `${list.length} device${list.length === 1 ? '' : 's'}` : '';

  $('rows').innerHTML = list.map((d) => `
    <tr>
      <td class="mono">${esc(d.ip)}<div class="sub">${esc(d.adapter || '')}</div></td>
      <td class="mono">${d.mac ? esc(d.mac) + `<span class="tag">${esc(d.macSource)}</span>` : `<span class="sub">${d.macSource === 'unavailable' ? 'not available' : 'reading…'}</span>`}</td>
      <td class="pn">${esc(d.catalog || '—')}</td>
      <td>${esc(d.productName)}<div class="sub">Product code ${esc(d.productCode)}</div></td>
      <td><span class="fw">${esc(d.firmware)}</span></td>
      <td class="mono">${esc(d.serial)}</td>
      <td>${esc(d.deviceTypeName)}<div class="sub">${esc(d.vendor)}</div></td>
      <td><div class="actions">
        <button class="small" data-copy="${esc(d.ip)}" title="Copy row">Copy</button>
        <button class="small" data-web="${esc(d.ip)}" title="Open the device's built-in web page">Web</button>
      </div></td>
    </tr>`).join('');
}

function deviceText(d) {
  return [
    `IP: ${d.ip}`, `MAC: ${d.mac || 'unknown'}`, `Part Number: ${d.catalog || '—'}`,
    `Product: ${d.productName}`, `Firmware: ${d.firmware}`, `Serial: ${d.serial}`,
    `Type: ${d.deviceTypeName}`, `Vendor: ${d.vendor}`
  ].join('\n');
}

async function doScan(adapterName) {
  if (busy) return;
  const extra = $('txt-extra').value.split(/[\s,;]+/).filter(Boolean);
  setBusy(true);
  await scannerAPI.scan({
    adapter: adapterName ?? ($('sel-adapter').value || undefined),
    sweep: $('chk-sweep').checked,
    extraTargets: extra
  });
  setBusy(false);
}

scannerAPI.onScanEvent((evt) => {
  switch (evt.type) {
    case 'start': setBusy(true); setStatus('Scanning…'); break;
    case 'status': setStatus(evt.message); break;
    case 'link': setStatus(evt.message); break;
    case 'link-up':
      if ($('chk-auto').checked) {
        setStatus(`${evt.message} — scanning…`);
        setTimeout(() => doScan(evt.adapter.name), 1500);
      } else {
        setStatus(`${evt.message} — press Scan Now.`);
      }
      break;
    case 'device':
      devices.set(evt.device.ip, evt.device);
      renderDevices();
      break;
    case 'error': setStatus(evt.message, true); break;
    case 'done':
      setBusy(false);
      setStatus(evt.count
        ? `Scan complete — ${evt.count} EtherNet/IP device(s) found. ${new Date().toLocaleTimeString()}`
        : 'Scan complete — no EtherNet/IP devices answered. Check the cable, subnet, and firewall (UDP/TCP 44818).');
      break;
  }
});

scannerAPI.onAdapters((list) => { adapters = list; renderAdapters(); });

$('btn-scan').addEventListener('click', () => doScan());
$('btn-clear').addEventListener('click', () => { devices.clear(); renderDevices(); setStatus('Cleared.'); });
$('btn-export').addEventListener('click', async () => {
  const res = await scannerAPI.exportCsv([...devices.values()]);
  if (res.saved) setStatus(`Saved ${res.filePath}`);
});
$('chk-auto').addEventListener('change', (e) => {
  try { localStorage.setItem('autoScan', e.target.checked ? '1' : '0'); } catch (_) { /* ignore */ }
});
$('rows').addEventListener('click', async (e) => {
  const copy = e.target.closest('[data-copy]');
  const web = e.target.closest('[data-web]');
  if (copy) {
    await navigator.clipboard.writeText(deviceText(devices.get(copy.dataset.copy)));
    setStatus(`Copied ${copy.dataset.copy} to clipboard.`);
  }
  if (web) scannerAPI.openWeb(web.dataset.web);
});

// ── Theme: system / light / dark ──
function applyTheme(mode) {
  if (mode === 'light' || mode === 'dark') document.documentElement.dataset.theme = mode;
  else delete document.documentElement.dataset.theme;
  document.querySelectorAll('[data-theme-btn]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.themeBtn === mode)));
  if (scannerAPI.setTheme) scannerAPI.setTheme(mode); // keeps the Windows title bar in sync
  try { localStorage.setItem('theme', mode); } catch (_) { /* ignore */ }
}
document.querySelectorAll('[data-theme-btn]').forEach((b) => b.addEventListener('click', () => applyTheme(b.dataset.themeBtn)));
(function initTheme() {
  let mode = 'system';
  try { mode = localStorage.getItem('theme') || 'system'; } catch (_) { /* ignore */ }
  applyTheme(mode);
})();

(async function init() {
  try { $('chk-auto').checked = localStorage.getItem('autoScan') !== '0'; } catch (_) { /* ignore */ }
  adapters = await scannerAPI.getAdapters();
  renderAdapters();
  renderDevices();
  if (adapters.some((a) => !a.virtual)) doScan();
})();
