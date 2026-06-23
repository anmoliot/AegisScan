from typing import Any
import difflib

class RuleBasedRiskEngine:
    """
    Core logic for findings deduplication, category-based clustering,
    remediation template mapping, and summary generation.
    """
    @staticmethod
    def calculate_similarity(s1: str, s2: str) -> float:
        """
        Computes string similarity score between 0.0 and 1.0.
        """
        return difflib.SequenceMatcher(None, s1.lower(), s2.lower()).ratio()

    @classmethod
    def deduplicate_findings(cls, findings: list[dict[str, Any]], threshold: float = 0.8) -> list[dict[str, Any]]:
        """
        Deduplicates findings based on description and title similarity.
        """
        unique = []
        for f in findings:
            is_dup = False
            for u in unique:
                # Compare plugin and similarity of descriptions
                if f.get("plugin") == u.get("plugin"):
                    sim = cls.calculate_similarity(f.get("description", ""), u.get("description", ""))
                    if sim >= threshold:
                        is_dup = True
                        break
            if not is_dup:
                unique.append(f)
        return unique

    @staticmethod
    def cluster_findings(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """
        Clusters findings by category (e.g. sqli, xss, ssrf, idor).
        """
        clusters = {}
        for f in findings:
            cat = f.get("category", "generic")
            if cat not in clusters:
                clusters[cat] = []
            clusters[cat].append(f)
        return clusters

    @staticmethod
    def generate_remediation_summary(category: str) -> str:
        """
        Returns template remediation summary per vulnerability category.
        """
        templates = {
            "server-side-request-forgery": "Restrict outgoing HTTP calls at network and code level. Resolve target hostnames and verify against a public/private IP blocklist.",
            "broken-object-level-authorization": "Ensure that every access to resource models performs query-level checks matching the request context user ID.",
            "sql-injection": "Use parameterized queries or ORM models for all SQL executions. Avoid executing raw queries constructed with string concatenation.",
            "cross-site-scripting": "Apply context-appropriate output encoding in HTML templates and enforce strict Content Security Policies (CSP)."
        }
        return templates.get(category.lower(), "Review vulnerability details and apply secure coding principles to resolve findings.")
