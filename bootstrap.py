"""Create/update the local environment using the Python running this script."""
from datetime import datetime
from pathlib import Path
import subprocess
import sys


def main():
    if sys.version_info[:2] not in {(3, 12), (3, 13), (3, 14)}:
        raise RuntimeError('Use Python 3.14 (recommended), 3.13 or 3.12.')
    root = Path(__file__).resolve().parent
    backend = root / 'backend'
    environment = backend / '.venv'
    python = environment / 'Scripts' / 'python.exe'
    expected = f'{sys.version_info.major}.{sys.version_info.minor}'
    existing = None
    if python.exists():
        result = subprocess.run([str(python), '-c',
                                 'import sys; print(str(sys.version_info.major)+"."+str(sys.version_info.minor))'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            existing = result.stdout.strip()
    if environment.exists() and existing != expected:
        backup = backend / ('.venv-backup-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
        print('Preserving the previous environment at', backup.name, flush=True)
        environment.rename(backup)
    if not python.exists():
        subprocess.run([sys.executable, '-m', 'venv', str(environment)], check=True)
    print('Selected Python:', sys.version.split()[0], flush=True)
    subprocess.run([str(python), '-m', 'pip', 'install', '--upgrade', 'pip',
                    '--disable-pip-version-check'], check=True)
    subprocess.run([str(python), '-m', 'pip', 'install', '--only-binary=:all:',
                    '-r', str(backend / 'requirements.txt'),
                    '--disable-pip-version-check'], check=True)
    print('\nOpen http://127.0.0.1:8000/ after Application startup complete.', flush=True)
    print('Keep this window open. Press Ctrl+C to stop the server.', flush=True)
    return subprocess.call([str(python), '-m', 'uvicorn', 'main:app',
                            '--host', '127.0.0.1', '--port', '8000'], cwd=backend)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print('\nSetup/start failed:', error, flush=True)
        print('Check internet access and Python installation. Stop any old server before upgrading.', flush=True)
        raise SystemExit(1)
