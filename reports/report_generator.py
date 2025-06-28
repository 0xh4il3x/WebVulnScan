import os
from datetime import datetime

def generate(recon_data, headers_data, sqli_data, xss_data, sensitive_files_data, output_path):
    report_lines = []

    # Metadata Header
    report_lines.append("# 🛡️ WebVulnScan Report")
    report_lines.append("")
    report_lines.append(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"**Target:** {recon_data.get('url')}")
    report_lines.append("\n---\n")

    # Recon Section
    report_lines.append("## 🔍 Reconnaissance")
    report_lines.append(f"- **Status Code:** {recon_data.get('status_code')}")
    report_lines.append(f"- **Page Title:** {recon_data.get('title')}")
    if recon_data.get("tech"):
        report_lines.append(f"- **Detected Technologies:**")
        for tech in recon_data["tech"]:
            report_lines.append(f"  - {tech}")
    else:
        report_lines.append("- No technologies detected.")
    report_lines.append("\n---\n")

    # Headers Section
    report_lines.append("## 📦 Security Headers")
    if headers_data:
        for header in headers_data:
            if header["status"] == "present":
                report_lines.append(f"- ✅ **{header['name']}**: {header['value']}")
            else:
                report_lines.append(f"- ❌ **{header['name']}**: *Missing* — {header['description']}")
    else:
        report_lines.append("- Header scan failed or no data returned.")
    report_lines.append("\n---\n")

    # SQLi Section
    report_lines.append("## 💉 SQL Injection")
    if sqli_data:
        for vuln in sqli_data:
            report_lines.append(f"- ❗ **Parameter:** `{vuln['parameter']}`")
            report_lines.append(f"  - **Type:** {vuln['type']}")
            report_lines.append(f"  - **Payload:** `{vuln['payload']}`")
            report_lines.append(f"  - **URL:** {vuln['url']}")
            report_lines.append("")
    else:
        report_lines.append("- ✅ No SQL Injection vulnerabilities detected.")
    report_lines.append("\n---\n")

    # XSS Section
    report_lines.append("## ✴️ Cross-Site Scripting (XSS)")
    if xss_data:
        for vuln in xss_data:
            report_lines.append(f"- ❗ **Parameter:** `{vuln['parameter']}`")
            report_lines.append(f"  - **Payload:** `{vuln['payload']}`")
            report_lines.append(f"  - **URL:** {vuln['url']}")
            report_lines.append("")
    else:
        report_lines.append("- ✅ No XSS vulnerabilities detected.")
    report_lines.append("\n---\n")

    # Sensitive Files Section
    report_lines.append("## 📁 Sensitive Files & Open Directories")
    if sensitive_files_data:
        for item in sensitive_files_data:
            status_icon = {
                "found": "❗",
                "open_directory": "📂",
                "forbidden": "🔒",
                "not_found": "✅",
                "server_error": "❗",
                "redirect": "↪️",
                "unknown": "❓"
            }.get(item["status"], "❓")

            report_lines.append(f"- {status_icon} **{item['path']}** ({item['status']})")
            report_lines.append(f"  - **URL:** {item['url']}")
            if "details" in item and item["details"]:
                report_lines.append(f"  - **Details:** {item['details']}")
            report_lines.append("")
    else:
        report_lines.append("- No sensitive files or open directories found.")
    report_lines.append("\n---\n")

    # Save to file
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        print(f"[✓] Report successfully saved to {output_path}")
    except Exception as e:
        print(f"[!] Failed to write report: {e}")
