import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

DANGEROUS_FILE_EXTENSIONS = frozenset({
    # Windows Binaries & Installers
    'exe', 'scr', 'bat', 'cmd', 'msi', 'com', 'pif',
    # Disk Images & Containers
    'iso', 'img', 'vhd', 'vhdx',
    # Script Hosts
    'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'ps1', 'psm1',
    # Archives frequently packaging executables
    'zip', 'rar', '7z', 'tar', 'gz', 'cab',
    # Mobile & macOS payloads
    'apk', 'dmg', 'pkg', 'app', 'jar',
})

DANGEROUS_MIME_TYPES = frozenset({
    'application/x-msdownload',
    'application/x-dosexec',
    'application/x-msdos-program',
    'application/x-iso9660-image',
    'application/vnd.android.package-archive',
    'application/x-bat',
    'application/x-msi',
})

DOUBLE_EXT_PATTERN = re.compile(
    r'\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|mp4)\.(?:exe|scr|bat|cmd|vbs|js|ps1|hta|iso|msi)$',
    re.IGNORECASE,
)


def audit_download_payloads(
    soup: BeautifulSoup,
    response_headers: dict,
    target_url: str,
    findings: list,
) -> dict:
    """
    Inspects Content-Type, Content-Disposition headers, and DOM download elements.
    """
    headers = {k.lower(): v for k, v in response_headers.items()}
    content_type = headers.get('content-type', '').split(';')[0].strip().lower()
    content_disp = headers.get('content-disposition', '')

    filename = ''
    if 'filename=' in content_disp:
        parts = content_disp.split('filename=')[-1].strip().strip('"\'')
        filename = parts.split(';')[0].strip('"\'; ')

    # Check target URL path if header filename is empty
    if not filename:
        path = urlparse(target_url).path
        filename = path.rsplit('/', 1)[-1] if '/' in path else ''

    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    # 1. Check dangerous MIME or extension
    is_dangerous_mime = content_type in DANGEROUS_MIME_TYPES
    is_dangerous_ext = ext in DANGEROUS_FILE_EXTENSIONS

    if is_dangerous_mime or is_dangerous_ext:
        findings.append({
            'type': 'DANGEROUS_EXECUTABLE_DOWNLOAD',
            'flagged': True,
            'explanation': (
                f"The URL triggers the direct download of an executable or container payload "
                f"('{filename}' - {content_type or ext}). Drive-by downloads frequently deliver malware or ransom droppers."
            ),
        })

    # 2. Check for Double Extension Trap
    is_double_ext = bool(DOUBLE_EXT_PATTERN.search(filename))
    if is_double_ext:
        findings.append({
            'type': 'DOUBLE_EXTENSION_DECEPTION',
            'flagged': True,
            'explanation': (
                f"The payload filename '{filename}' employs a deceptive double extension (e.g. .pdf.exe). "
                'Attackers exploit hidden file extensions to trick users into executing binaries.'
            ),
        })

    # 3. DOM Auto-Download Inspection
    auto_download_elements = []
    if soup:
        download_links = soup.find_all('a', href=True, download=True)
        for link in download_links:
            href = link.get('href', '')
            dl_ext = href.rsplit('.', 1)[-1].lower() if '.' in href else ''
            if dl_ext in DANGEROUS_FILE_EXTENSIONS:
                auto_download_elements.append(href)

    if auto_download_elements:
        findings.append({
            'type': 'AUTOMATED_DRIVE_BY_DOWNLOAD',
            'flagged': True,
            'explanation': (
                f"Detected HTML download anchors configured to drop executable file types "
                f"({', '.join(auto_download_elements[:3])})."
            ),
        })

    return {
        'isExecutableDownload': is_dangerous_mime or is_dangerous_ext,
        'isDoubleExtension': is_double_ext,
        'downloadFilename': filename or None,
        'contentType': content_type,
        'autoDownloadAnchors': auto_download_elements[:5],
    }
