import os
import re
import json
import argparse
from datetime import datetime
from docxtpl import DocxTemplate, RichText

REPORT_DATA = "database/report-data"
PENTEST_REPORTS = "reports"
VULNERABILITY_DATABASE = os.path.join("database/vulndb", "vulnerability_database.json")
TEMPLATE_PATHS = {
    "default": "database/templates/pentest_report_template.docx",
    "retest": "database/templates/retest_report_template.docx"
}

severity_colors = {
    "critical": "C00000",
    "high": "ED7D32",
    "medium": "FFBF00",
    "low": "5B9BD5",
    "insignificant": "71AD47"
}

status_colors = {
    "PASS": severity_colors["insignificant"],
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
        "insignificant": 4
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

def collect_manual_data(is_retest=False):
    """Collect all necessary fields manually from user input."""
    today_date = datetime.today().strftime("%Y-%m-%d")
    
    print("\n📝 Please provide the following information:\n")
    
    report_data = {
        "Name": get_user_input("Pentester Name", required=True),
        "Email": get_user_input("Pentester Email", required=True),
        "ApplicationName": get_user_input("Application Name", required=True),
        "TicketNumber": get_user_input("Ticket/Reference Number", required=True),
        "PentestType": get_user_input("Pentest Type (e.g., Annual/SDLC/Custom)", "Annual"),
        "ProductionAccessibility": get_user_input("Production Accessibility (e.g., Yes/No/Partial)", "No"),
        "CINumber": get_user_input("CI Number", "N/A"),
        "RequesterName": get_user_input("Requester Name", required=True),
        "RequesterEmail": get_user_input("Requester Email", required=True),
        "PentestMethod": get_user_input("Pentest Method (Automated/Manual)", "Manual"),
        "ApplicationType": get_user_input("Application Type (Web/API/Mobile)", "API"),
        "Environment": get_user_input("Environment (UAT/DEV/Production)", "UAT"),
        "SubmissionDate": get_user_input("Submission Date (YYYY-MM-DD)", today_date)
    }
    
    if is_retest:
        report_data["PreviousPentestTicket"] = get_user_input("Previous Pentest Reference Number", required=True)
        report_data["PreviousPentestDate"] = get_user_input("Previous Pentest Date (YYYY-MM-DD)", required=True)
        
        if report_data["PreviousPentestDate"]:
            try:
                datetime.strptime(report_data["PreviousPentestDate"], "%Y-%m-%d")
            except ValueError:
                print("⚠️ Invalid date format. Please use YYYY-MM-DD.")
                report_data["PreviousPentestDate"] = ""
        
        report_data["PreviousPentesterName"] = get_user_input("Previous Pentester Name", required=True)
    else:
        report_data["PreviousPentestTicket"] = ""
        report_data["PreviousPentestDate"] = ""
        report_data["PreviousPentesterName"] = ""
    
    return report_data

def handle_new_report(args):
    """Handle creation of a new pentest report."""
    report_data = collect_manual_data(is_retest=args.retest)
    
    # Collect In-Scope Endpoints
    report_data["Endpoints"] = get_multiline_input("\nEndpoints")

    add_vulns = get_user_input("\nDo you want to include vulnerabilities in the report now? Press Enter to continue or type 'no' for empty pentest report template.", "yes").lower()
    
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

    safe_app_name = re.sub(r'[\\/:"*?<>|]+', "_", report_data['ApplicationName'])
    file_name = f"{report_data['TicketNumber']} - {safe_app_name}.json"
    save_to_file(report_data, file_name)
    render_and_save_docx(report_data, use_retest_template=args.retest)

def handle_select_vulnerabilities(args):
    """Handle selecting vulnerabilities for an existing report."""
    report_file = list_json_reports()
    if not report_file:
        print("❌ No report selected. Exiting...")
        return
    
    report_data = load_from_file(os.path.join(REPORT_DATA, report_file))
    if not report_data:
        return
    
    print("\n✅ Loaded report:", report_file)
    selected_vulns = list_and_select_vulnerabilities()
    
    if selected_vulns:
        colorize_and_attach_vulnerabilities(report_data, selected_vulns)
        overall_severity_text, risk_status_text = determine_overall_risk(selected_vulns, severity_colors)
        report_data["OverallSeverity"] = overall_severity_text
        report_data["RiskStatus"] = risk_status_text
        cleaned_data = clean_report_data(report_data)
        render_and_save_docx(cleaned_data, use_retest_template=args.retest)
        save_to_file(cleaned_data, report_file)
        print("\n✅ Selected vulnerabilities added to the report.\n")
    else:
        print("\n❌ No vulnerabilities selected.")

def handle_import_file(args):
    """Handle importing an existing report file."""
    if args.import_file is True:
        report_file = list_json_reports()
    elif args.import_file:
        report_path = os.path.join(REPORT_DATA, args.import_file)
        report_file = args.import_file if os.path.exists(report_path) else list_json_reports()
    else:
        report_file = None
    
    if not report_file:
        print("❌ No report selected. Exiting...")
        return
    
    report_data = load_from_file(os.path.join(REPORT_DATA, report_file))
    if report_data:
        cleaned_data = clean_report_data(report_data)
        render_and_save_docx(cleaned_data, use_retest_template=args.retest)

def determine_overall_risk(vulnerabilities, severity_colors):
    """
    Determines the highest severity among vulnerabilities and assigns a PASS/FAIL status.
    Returns formatted severity and status separately.
    """
    severity_levels = ["insignificant", "low", "medium", "high", "critical"]
    highest_severity = "insignificant"

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low").lower()
        if severity == "informational":
            severity = "insignificant"
        if severity_levels.index(severity) > severity_levels.index(highest_severity):
            highest_severity = severity

    status = "PASS" if highest_severity in ["insignificant", "low"] else "FAIL"
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
    ticket_number = report_data.get('TicketNumber', 'TICKET-001')
    return f"{ticket_number} - {safe_app_name}"

def clean_report_data(data):
    """Recursively convert any non-serializable objects (like RichText) to strings."""
    if isinstance(data, dict):
        return {key: clean_report_data(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [clean_report_data(item) for item in data]
    elif hasattr(data, '__class__') and data.__class__.__name__ == 'RichText':
        return str(data)
    else:
        return data

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
        clean_vulns = clean_report_data(vulnerabilities)
        json.dump(clean_vulns, f, indent=4)
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
        "severity": get_choice_input("\nSeverity (Insignificant/Low/Medium/High/Critical)", 
                                     ["Insignificant", "Low", "Medium", "High", "Critical"]),
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

def list_json_reports():
    """Lists all available report JSON files and allows user to select one."""
    if not os.path.exists(REPORT_DATA):
        os.makedirs(REPORT_DATA)

    json_files = [f for f in os.listdir(REPORT_DATA) if f.endswith(".json")]

    if not json_files:
        print("\n❌ No report files found in 'database/report-data/' folder.")
        return None

    print("\n🔹 Available Reports:\n")
    for i, file in enumerate(json_files, start=1):
        print(f"{i}. {file}")

    while True:
        choice = input("\nEnter the number of the report to use (or press Enter to cancel): ").strip()
        if not choice:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(json_files):
            return json_files[int(choice) - 1]
        print("❌ Invalid selection. Please enter a valid number.")

def load_from_file(file_path):
    """Load report data from a JSON file with detailed error messages."""
    try:
        full_path = os.path.abspath(file_path)
        print(f"\n📂 Attempting to load: {full_path}")
        
        with open(full_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: File not found - {full_path}")
    except json.JSONDecodeError as e:
        print(f"❌ JSON format issue in '{full_path}': {e.msg} at line {e.lineno}, column {e.colno}")
    except UnicodeDecodeError:
        print(f"❌ Encoding error: '{full_path}' is not properly encoded in UTF-8.")
    except Exception as e:
        print(f"❌ Unexpected error while loading '{full_path}': {e}")
    return None

def save_to_file(data, file_name):
    """Save collected input data to a JSON file."""
    os.makedirs(REPORT_DATA, exist_ok=True)
    file_path = os.path.join(REPORT_DATA, file_name)

    clean_data = clean_report_data(data)

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(clean_data, f, indent=4)

    print(f"\n📄 Report Data saved in: {os.path.abspath(file_path)}")

def format_endpoints(report_data):
    """Format endpoints as RichText with bullet points."""
    endpoints_richtext = RichText()
    endpoints = report_data.get("Endpoints", [])

    if isinstance(endpoints, str):
        endpoints = [line.strip() for line in endpoints.strip().splitlines() if line.strip()]

    for url in endpoints:
        endpoints_richtext.add(f"\t• {url}\n")
    report_data["Endpoints"] = endpoints_richtext

def render_and_save_docx(report_data, use_retest_template=False):
    """Render the report data into a Word document and save it."""
    format_endpoints(report_data)
    folder_name = report_folder_name(report_data)
    output_folder = os.path.join(PENTEST_REPORTS, folder_name)
    os.makedirs(output_folder, exist_ok=True)
    file_name = f"{folder_name}.docx"

    template_path = TEMPLATE_PATHS["retest"] if use_retest_template else TEMPLATE_PATHS["default"]
    
    if not os.path.exists(template_path):
        print(f"❌ Template file not found: {template_path}")
        print("Please ensure the template file exists in the specified location.")
        return
    
    try:
        template = DocxTemplate(template_path)
        template.render(report_data)
        output_path = os.path.join(output_folder, file_name)
        template.save(output_path)
        print(f"\n✅ Report docx saved in: {os.path.abspath(output_path)}\n")
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

    print("\nEnter the numbers of vulnerabilities to add in the Report (comma-separated, e.g., 1,3) or 'all':\n")
    choice = input("> ").strip()

    if choice.lower() == "all":
        return vulnerabilities
    else:
        indices = [int(x.strip()) - 1 for x in choice.split(",") if x.strip().isdigit()]
        selected_vulns = [vulnerabilities[i] for i in indices if 0 <= i < len(vulnerabilities)]
        return selected_vulns

def main():
    parser = argparse.ArgumentParser(description="Pentest Report Generator - Generate professional DAST reports")
    parser.add_argument("-n", "--new-report", action="store_true", help="Create a new pentest report manually.")
    parser.add_argument("-i", "--import-file", nargs="?", const=True, help="Import pre-filled data from a JSON file.")
    parser.add_argument("-s", "--select-vulnerabilities", action="store_true", help="Select vulnerabilities to add to an existing report.")
    parser.add_argument("-a", "--add-vulnerabilities", action="store_true", help="Add a new vulnerability to the database.")
    parser.add_argument("-r", "--retest", action="store_true", help="Use the retest report template.")
    
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.new_report:
        handle_new_report(args)
    elif args.select_vulnerabilities:
        handle_select_vulnerabilities(args)
    elif args.import_file is not None:
        handle_import_file(args)
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
