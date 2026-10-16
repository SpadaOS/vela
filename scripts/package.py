"""Build and exercise a ZIP outside the checkout, with exact binary hashes."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
GUESTS = ('hello hello-musl hello-dyn ld-musl-x86_64.so.1 torture tls bench file-io '
          'fs-exec fork-test pipe-a pipe-b busybox pthread-test signal-test socket-test '
          'network-concurrency-test epoll-test signal-wait-test socket-edge-test '
          'signal-lifecycle-test island-test').split()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tag')
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
    version = next(p['version'] for p in metadata['packages'] if p['name']=='vela-cli')
    if args.tag and args.tag != f'v{version}':
        raise SystemExit(f'tag {args.tag} does not match v{version}')
    release = ROOT/'release'
    release.mkdir(exist_ok=True)
    name = f'vela-v{version}-windows-x64'
    archive = release/f'{name}.zip'
    with tempfile.TemporaryDirectory(prefix='vela-package-') as staging:
        package = Path(staging)/name
        (package/'guest/bin').mkdir(parents=True)
        (package/'scripts').mkdir()
        shutil.copy2(ROOT/'target/release/vela.exe', package/'vela.exe')
        for file in ['README.md','LICENSE','SECURITY.md','CHANGELOG.md','CONTRIBUTING.md']:
            shutil.copy2(ROOT/file,package/file)
        shutil.copytree(ROOT/'docs',package/'docs')
        shutil.copy2(ROOT/'guest/README.md',package/'guest/README.md')
        for file in ['acceptance.py','verify.ps1']:
            shutil.copy2(ROOT/'scripts'/file,package/'scripts'/file)
        for guest in GUESTS:
            shutil.copy2(ROOT/'guest/bin'/guest,package/'guest/bin'/guest)
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as output:
            for file in sorted(package.rglob('*')):
                if file.is_file(): output.write(file,file.relative_to(staging))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(f'{digest}  {archive.name}\n',encoding='ascii')
    report=release/'package-validation'
    report.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='vela-extracted-') as extracted:
        with zipfile.ZipFile(archive) as source: source.extractall(extracted)
        package=Path(extracted)/name
        subprocess.run([sys.executable,str(package/'scripts/acceptance.py'),
                        '--exe',str(package/'vela.exe'),'--guests',str(package/'guest/bin'),
                        '--report',str(report),'--busybox','--threads','--signals','--network'],
                       cwd=package,check=True,timeout=600)
    state=dict(version=version,commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
               dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
               path=str(archive),bytes=archive.stat().st_size,sha256=digest,
               validation=str(report/'acceptance.json'))
    (release/'package.json').write_text(json.dumps(state,indent=2),encoding='utf-8')
    print(json.dumps(state,indent=2))

if __name__=='__main__': main()
