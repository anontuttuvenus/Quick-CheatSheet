import os
import re
import json
import argparse
from datetime import datetime
from docxtpl import DocxTemplate, RichText

PENTEST_REPORTS = "reports"
VULNERABILITY_DATABASE = os.path.join("database/vulndb", "vulnerability_database.json")
TEMPLATE_PATH = "database/templates/pentest_report_template.docx"

severity_colors = {
    "critical": "C00000",
    "high": "ED7D31",
    "medium": "FFBF00",
    "low": "5B9BD5",
    "informational": "71AD47"
}

status_colors = {
    "PASS": severity_colors["informational"],
    "FAIL": severity_colors["critical"]
}

def color_code_field(field_value, color_map):
    """Returns a RichText object with text colored according to the given color_map."""
    rt = RichText()
    rt.add(field_value, color=color_map.get(field_value.lower(), "000000"))
    return rt

def colorize_and_attach_vulnerabilities(report_data, vulnerabilities):
    """
    Color-code each vulnerability's severity, impact, and likelihood, 
    then attach them to the report data. Also convert bold markdown to RichText and handle bullet points.
    """
    def convert_bold_and_bullets_to_richtext(text):
        if not text:
            return RichText()
        rt = RichText()
        lines = text.splitlines()
        for line in lines:
            if line.strip().startswith("-"):
                rt.add("• ")
                line = line.strip()[1:].strip()
            parts = re.split(r'(\*\*.*?\*\*)', line)
            for part in parts:
                if part.startswith("**") and part.endswith("**"):
                    rt.add(part[2:-2], bold=True)
                else:
                    rt.add(part)
            rt.add("\n")
        return rt

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4
    }
    vulnerabilities.sort(key=lambda v: severity_order.get(v.get("severity", "").lower(), 5))
    
    for vuln in vulnerabilities:
        vuln["severity_colored"] = color_code_field(vuln.get("severity", "Low"), severity_colors)
        vuln["impact_colored"] = color_code_field(vuln.get("impact", "Low"), severity_colors)
        vuln["likelihood_colored"] = color_code_field(vuln.get("likelihood", "Low"), severity_colors)

        # Convert text fields to RichText with bold and bullet support
        if isinstance(vuln.get("attack_scenario"), str):
            vuln["attack_scenario"] = convert_bold_and_bullets_to_richtext(vuln["attack_scenario"])
        
        if isinstance(vuln.get("recommendation"), str):
            vuln["recommendation"] = convert_bold_and_bullets_to_richtext(vuln["recommendation"])
        
        if isinstance(vuln.get("description"), str):
            vuln["description"] = convert_bold_and_bullets_to_richtext(vuln["description"])
        
        # Handle Steps to Reproduce field
        if isinstance(vuln.get("reproduce"), str):
            vuln["reproduce"] = convert_bold_and_bullets_to_richtext(vuln["reproduce"])
        else:
            vuln["reproduce"] = convert_bold_and_bullets_to_richtext("[Add steps to reproduce here]")

    report_data["vulnerabilities"] = vulnerabilities

def collect_manual_data():
    """Collect all necessary fields manually from user input."""
    today_date = datetime.today().strftime("%Y-%m-%d")
    
    print("\n📝 Please provide the following information:\n")
    
    report_data = {
        "Name": get_user_input("Pentester Name", required=True),
        "Email": get_user_input("Pentester Email", required=True),
        "ApplicationName": get_user_input("Application Name", required=True),
        "ApplicationType": get_user_input("Application Type (Web/API/Mobile)", "API"),
        "PentestType": get_user_input("Pentest Type (Annual/SDLC)", "SDLC"),
        "RequesterName": get_user_input("Requester Name", required=True),
        "RequesterEmail": get_user_input("Requester Email", required=True),
        "SubmissionDate": get_user_input("Submission Date (YYYY-MM-DD)", today_date),
        "TicketNumber": "N/A"  # Default value, not prompted
    }
    
    return report_data

def handle_new_report():
    """Handle creation of a new pentest report."""
    report_data = collect_manual_data()
    
    # Collect In-Scope Endpoints
    report_data["Endpoints"] = get_multiline_input("\nEndpoints")

    add_vulns = get_user_input("\nDo you want to include vulnerabilities in the report now? Press Enter to continue or type 'no' for empty report.", "yes").lower()
    
    if add_vulns == "yes":
        selected_vulns = list_and_select_vulnerabilities()
        if selected_vulns:
            colorize_and_attach_vulnerabilities(report_data, selected_vulns)
            overall_severity_text, risk_status_text = determine_overall_risk(selected_vulns, severity_colors)
            report_data["OverallSeverity"] = overall_severity_text
            report_data["RiskStatus"] = risk_status_text
        else:
            report_data["vulnerabilities"] = []
            report_data["OverallSeverity"] = None
            report_data["RiskStatus"] = None
    else:
        report_data["vulnerabilities"] = []
        report_data["OverallSeverity"] = None
        report_data["RiskStatus"] = None

    # Generate report directly
    render_and_save_docx(report_data)

def determine_overall_risk(vulnerabilities, severity_colors):
    """
    Determines the highest severity among vulnerabilities and assigns a PASS/FAIL status.
    Returns formatted severity and status separately.
    """
    severity_levels = ["informational", "low", "medium", "high", "critical"]
    highest_severity = "informational"

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low").lower()
        if severity == "insignificant":
            severity = "informational"
        if severity_levels.index(severity) > severity_levels.index(highest_severity):
            highest_severity = severity

    status = "PASS" if highest_severity in ["informational", "low"] else "FAIL"
    status_color = status_colors[status]

    severity_text = RichText()
    severity_text.add(highest_severity.capitalize(), color=severity_colors[highest_severity], bold=True)

    status_text = RichText()
    status_text.add(status, color=status_color, bold=True)

    return severity_text, status_text

def get_user_input(prompt, default="", required=False):
    """Helper function to get user input with an optional default value and required validation."""
    prompt_text = f"{prompt} [{default}]: " if default else f"{prompt}: "
    while True:
        user_input = input(prompt_text).strip()
        if required and not user_input:
            print("❌ This field is required. Please enter a valid value.")
        else:
            return user_input if user_input else default

def get_choice_input(prompt, choices):
    """Prompt user to choose from predefined options (case-insensitive)."""
    choices_map = {choice.lower(): choice for choice in choices}
    while True:
        value = get_user_input(prompt).strip()
        if value.lower() in choices_map:
            return choices_map[value.lower()]
        print(f"❌ Invalid choice. Valid options: {', '.join(choices)}")

def report_folder_name(report_data):
    """Generate a safe folder name for the report."""
    safe_app_name = re.sub(r'[\\/:"*?<>|]+', "_", report_data.get('ApplicationName', 'Report'))
    return safe_app_name

def load_vulnerabilities():
    """Load predefined vulnerabilities from a JSON file."""
    try:
        with open(VULNERABILITY_DATABASE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_vulnerabilities(vulnerabilities):
    """Save vulnerabilities to the JSON file."""
    os.makedirs(os.path.dirname(VULNERABILITY_DATABASE), exist_ok=True)
    with open(VULNERABILITY_DATABASE, "w", encoding="utf-8") as f:
        json.dump(vulnerabilities, f, indent=4)
    print(f"\n📦 Vulnerability database: {os.path.abspath(VULNERABILITY_DATABASE)}")

def add_vulnerabilities():
    """Prompt the user to add a new vulnerability to the database, avoiding duplicates."""
    print("\n🔹 Adding a New Vulnerability\n")

    title = get_user_input("Vulnerability Title", required=True)
    vulnerabilities = load_vulnerabilities()

    existing_vuln = next((v for v in vulnerabilities if v["title"].lower() == title.lower()), None)

    if existing_vuln:
        print("\n⚠️ A vulnerability with this title already exists:")
        print(f"\nTitle: {existing_vuln['title']}")
        print(f"Severity: {existing_vuln['severity']}")
        print(f"Description: {existing_vuln.get('description', '')[:100]}...")

        choice = get_user_input("\nDo you want to overwrite this vulnerability? (yes/no)", "no").lower()
        if choice != "yes":
            print("\n❌ New entry not added. Keeping the existing vulnerability.")
            return

    vulnerability = {
        "title": title,
        "description": get_multiline_input("\nDescription (Plain text only)"),
        "severity": get_choice_input("\nSeverity (Informational/Low/Medium/High/Critical)", 
                                     ["Informational", "Low", "Medium", "High", "Critical"]),
        "impact": get_choice_input("\nImpact (Low/Medium/High/Critical)", 
                                   ["Low", "Medium", "High", "Critical"]),
        "likelihood": get_choice_input("\nLikelihood (Low/Medium/High/Critical)", 
                                       ["Low", "Medium", "High", "Critical"]),
        "attack_scenario": get_multiline_input("\nAttack & Risk Scenario (Plain text only)"),
        "reproduce": get_multiline_input("\nSteps to Reproduce (Plain text only)"),
        "recommendation": get_multiline_input("\nRecommendations (Plain text only)"),
        "references": get_multiline_input("\nReference URLs", input_type="url")
    }

    if existing_vuln:
        vulnerabilities = [v if v["title"].lower() != title.lower() else vulnerability for v in vulnerabilities]
    else:
        vulnerabilities.append(vulnerability)

    save_vulnerabilities(vulnerabilities)
    print("\n✅ New vulnerability added successfully!\n")

def get_multiline_input(prompt, input_type="text"):
    """Helper function to get multi-line user input until 'stop' is entered."""
    print(f"{prompt} (Type 'stop' on a new line to finish):\n")
    lines = []
    while True:
        line = input()
        if line.strip().lower() == "stop":
            break
        lines.append(line.strip())
    return lines if input_type == "url" else "\n".join(lines)

def format_endpoints(report_data):
    """Format endpoints as plain text without bullet points."""
    endpoints_richtext = RichText()
    endpoints = report_data.get("Endpoints", [])

    if isinstance(endpoints, str):
        endpoints = [line.strip() for line in endpoints.strip().splitlines() if line.strip()]

    for url in endpoints:
        endpoints_richtext.add(f"{url}\n")
    report_data["Endpoints"] = endpoints_richtext

def render_and_save_docx(report_data):
    """Render the report data into a Word document and save it."""
    format_endpoints(report_data)
    folder_name = report_folder_name(report_data)
    output_folder = os.path.join(PENTEST_REPORTS, folder_name)
    os.makedirs(output_folder, exist_ok=True)
    file_name = f"{folder_name}.docx"
    
    if not os.path.exists(TEMPLATE_PATH):
        print(f"❌ Template file not found: {TEMPLATE_PATH}")
        print("Please ensure the template file exists in the specified location.")
        return
    
    try:
        template = DocxTemplate(TEMPLATE_PATH)
        template.render(report_data)
        output_path = os.path.join(output_folder, file_name)
        template.save(output_path)
        print(f"\n✅ Report saved in: {os.path.abspath(output_path)}\n")
    except Exception as e:
        print(f"\n❌ Error rendering template: {e}")
        print("Please check your template file for any syntax errors or missing placeholders.")

def list_and_select_vulnerabilities():
    """Display vulnerabilities and allow the user to select which ones to add to the report."""
    vulnerabilities = load_vulnerabilities()

    if not vulnerabilities:
        print("❌ No vulnerabilities found in the database.")
        return []

    print("\n🔹 Available Vulnerabilities in the database:\n")
    for i, vuln in enumerate(vulnerabilities, start=1):
        print(f"{i}. {vuln.get('title', 'Untitled')}")

    print("\nEnter the numbers of vulnerabilities to add (comma-separated, e.g., 1,3) or 'all':\n")
    choice = input("> ").strip()

    if choice.lower() == "all":
        return vulnerabilities
    else:
        indices = [int(x.strip()) - 1 for x in choice.split(",") if x.strip().isdigit()]
        selected_vulns = [vulnerabilities[i] for i in indices if 0 <= i < len(vulnerabilities)]
        return selected_vulns

def main():
    parser = argparse.ArgumentParser(description="Pentest Report Generator - Generate professional DAST reports")
    parser.add_argument("-n", "--new-report", action="store_true", help="Create a new pentest report")
    parser.add_argument("-a", "--add-vulnerabilities", action="store_true", help="Add a new vulnerability to the database")
    
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.new_report:
        handle_new_report()
    elif args.add_vulnerabilities:
        add_vulnerabilities()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Execution interrupted by user. Exiting gracefully.\n")
        exit(0)
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}")
        print("Please check your configuration and try again.")
        exit(1)
