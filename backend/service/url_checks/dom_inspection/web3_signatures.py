import re
from bs4 import BeautifulSoup

WEB3_DRAINER_PATTERNS = {
    'ETH_SIGN': re.compile(
        r'''(?:ethereum\.request\s*\(\s*\{\s*method\s*:\s*['"]eth_sign['"]|\.send\s*\(\s*['"]eth_sign['"])''',
        re.IGNORECASE,
    ),
    'NFT_SET_APPROVAL': re.compile(
        r'''(?:setApprovalForAll\s*\(\s*[^,]+,\s*(?:true|1|!0)\s*\)|setApprovalForAll)''',
        re.IGNORECASE,
    ),
    'PERMIT2_ALLOWANCE': re.compile(
        r'''(?:PermitSingle|PermitBatch|permit2|PermitTransferFrom|SignatureTransfer)''',
        re.IGNORECASE,
    ),
    'SEAPORT_ORDER_DRAIN': re.compile(
        r'''(?:fulfillAdvancedOrder|validate\s*\(\s*OrderComponents|fulfillAvailableOrders)''',
        re.IGNORECASE,
    ),
    'WALLET_CONNECT_HIJACK': re.compile(
        r'''(?:wc_session|wc@2:session|wc_peerMeta|walletconnect\.org/wallet)''',
        re.IGNORECASE,
    ),
    'STEALTH_CREATE2': re.compile(
        r'''(?:getCreate2Address|create2\s*\(\s*salt)''',
        re.IGNORECASE,
    ),
}


def audit_web3_signatures(soup: BeautifulSoup, findings: list) -> dict:
    """
    Scans inline scripts and script text for cryptocurrency wallet drainer signatures.
    """
    matched_threats: list[str] = []
    scripts = soup.find_all('script')

    combined_script_body = ' '.join([s.string for s in scripts if s.string])

    for sig_name, pattern in WEB3_DRAINER_PATTERNS.items():
        if pattern.search(combined_script_body):
            matched_threats.append(sig_name)

    if 'ETH_SIGN' in matched_threats:
        findings.append({
            'type': 'WEB3_BLIND_SIGN_DRAINER',
            'flagged': True,
            'explanation': (
                "The page contains code invoking 'eth_sign'. Adversaries use blind "
                'eth_sign calls to trick users into signing unreadable transaction payloads that drain crypto assets.'
            ),
        })

    if 'NFT_SET_APPROVAL' in matched_threats or 'PERMIT2_ALLOWANCE' in matched_threats:
        findings.append({
            'type': 'WEB3_PERMIT2_ALLOWANCE_DRAINER',
            'flagged': True,
            'explanation': (
                "The page contains automated NFT/Token allowance drainer signatures "
                "('setApprovalForAll' or 'Permit2'). These methods grant third-party contracts "
                'unilateral permission to transfer your digital assets.'
            ),
        })

    return {
        'hasWeb3DrainerSignatures': len(matched_threats) > 0,
        'detectedSignatures': matched_threats,
    }
