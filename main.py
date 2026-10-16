"""
================================================================================
CyberCloud9 & Cyber Intelligence Suite. Developed by PinoyUnknown ~ TeamWhiteHatDEv
================================================================================
Theme: CyberSecurityPro-Theme (Neon Transparent HUD Style Window Frames)
Developers:
- Team White Hat: https://github.com/unidentifiedcyberghost
- Repository:     https://github.com/PinoyUnknown/CyberCloud9

Usage:
  python main.py               -> Launches the interactive CyberSecurityPro-Theme GUI
  python main.py --self-test   -> Runs non-invasive verification of both engines & GUI
  python main.py --backup      -> Archives a version snapshot into OldVersion/
================================================================================
"""

import sys
import json
import argparse

from core import __version__, __theme__, __repo_url__, __dev_url__
from core.security_guard import SecurityGuard
from core.cyber_cloud9 import run_full_cybercloud9_audit, generate_origin_firewall_rules
from core.cyber_intel import CyberIntelligenceSuite
from core.version_backup import VersionBackupManager


def run_self_test() -> int:
    print("=" * 80)
    print("CyberCloud9 & Cyber Intelligence Suite. Developed by PinoyUnknown ~ TeamWhiteHatDEv")
    print(f"Version: v{__version__} | Theme: {__theme__}")
    print(f"Developer: Team White Hat - {__dev_url__} ; {__repo_url__}")
    print("=" * 80)

    # 1. Verify .gitignore Credential Guard
    guard = SecurityGuard.verify_gitignore_guard()
    print(f"[1/4] SecurityGuard .gitignore Check: {guard['verdict']} (Hardened={guard['is_hardened']})")
    assert guard["is_hardened"], f"Missing .gitignore patterns: {guard['missing_patterns']}"

    # 2. Verify Input Sanitizer & Secret Redactor
    ok_safe, _, _ = SecurityGuard.sanitize_target_input("cloudflare.com")
    ok_bad, _, _ = SecurityGuard.sanitize_target_input("example.com; rm -rf /")
    assert ok_safe is True and ok_bad is False, "Input sanitizer check failed"
    masked = SecurityGuard.mask_secret("cf_secret_token_1234567890abcdef")
    assert "***" in masked, "Secret masking check failed"
    print(f"[2/4] SecurityGuard Sanitizer & Secret Masker: PASS ({masked})")

    # 3. Verify CyberCloud9 Engine
    c9_res = run_full_cybercloud9_audit("127.0.0.1")
    fw_ufw = generate_origin_firewall_rules("ufw")
    assert "posture_score" in c9_res and "integrity_sha256" in c9_res
    assert "173.245.48.0/20" in fw_ufw
    print(
        f"[3/4] CyberCloud9 Engine Test: PASS "
        f"(Score={c9_res['posture_score']}/100, Status={c9_res['status']}, SHA256={c9_res['integrity_sha256'][:16]}...)"
    )

    # 4. Verify Cyber Intelligence Suite Engine
    intel = CyberIntelligenceSuite(timeout=3.0)
    dossier = intel.run_full_intelligence("127.0.0.1")
    assert "modules" in dossier and "evidence_correlation" in dossier and "integrity_sha256" in dossier
    print(
        f"[4/4] Cyber Intelligence Suite Test: PASS "
        f"(Modules={len(dossier['modules'])}, Evidence={len(dossier['evidence_correlation'])}, "
        f"SHA256={dossier['integrity_sha256'][:16]}...)"
    )

    print("=" * 80)
    print("ALL DEFENSIVE ENGINES & SECURITY LAYERS VERIFIED SUCCESSFULLY!")
    print("=" * 80)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="CyberCloud9 & Cyber Intelligence Suite. Developed by PinoyUnknown ~ TeamWhiteHatDEv"
    )
    parser.add_argument("--self-test", action="store_true", help="Run automated verification of all engines and security guards")
    parser.add_argument("--backup", action="store_true", help="Create a version snapshot inside OldVersion/")
    parser.add_argument("--audit-domain", type=str, help="Run CLI CyberCloud9 Origin Shield Audit on a domain")
    parser.add_argument("--intel-target", type=str, help="Run CLI Cyber Intelligence Suite OSINT on a target")
    args = parser.parse_args()

    if args.backup:
        mgr = VersionBackupManager()
        meta = mgr.create_version_snapshot(f"v{__version__}", "CLI Version Backup Snapshot")
        print(f"[+] Created OldVersion backup snapshot: {meta['path']} ({meta['files_count']} files)")
        return

    if args.self_test:
        sys.exit(run_self_test())

    if args.audit_domain:
        res = run_full_cybercloud9_audit(args.audit_domain)
        print(json.dumps(res, indent=2))
        return

    if args.intel_target:
        engine = CyberIntelligenceSuite()
        res = engine.run_full_intelligence(args.intel_target)
        print(json.dumps(res, indent=2))
        return

    from gui.main_window import launch_application
    launch_application()


if __name__ == "__main__":
    main()
