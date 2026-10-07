from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

data = [
    ["timestamp","host","user","event_type","source","destination","process","asset_criticality"],
    ["2026-10-08 00:00:00","host-20","scanner","scan","10.0.0.5","10.0.0.20","nmap","5"],
    ["2026-10-08 00:05:00","host-20","alice","login_success","10.0.0.5","10.0.0.20","sshd","5"],
    ["2026-10-08 00:10:00","host-20","alice","powershell","10.0.0.20","10.0.0.20","powershell","5"],
    ["2026-10-08 00:15:00","host-20","alice","network_discovery","10.0.0.20","10.0.0.0/24","net.exe","5"],
    ["2026-10-08 00:20:00","host-20","alice","credential_dump","10.0.0.20","10.0.0.20","lsass","5"],
    ["2026-10-08 00:25:00","host-20","alice","remote_login","10.0.0.20","10.0.0.30","rdp","5"],
    ["2026-10-08 00:30:00","host-30","alice","archive","10.0.0.30","10.0.0.30","7z","4"],
    ["2026-10-08 00:35:00","host-30","alice","upload","10.0.0.30","203.0.113.10","curl","4"],
    ["2026-10-08 00:40:00","host-30","system","ransomware","10.0.0.30","10.0.0.30","cryptolocker","5"],
    ["2026-10-08 00:45:00","host-10","bob","scan","10.0.0.5","10.0.0.10","nmap","3"],
    ["2026-10-08 00:50:00","host-10","bob","login_success","10.0.0.5","10.0.0.10","sshd","3"],
    ["2026-10-08 00:55:00","host-10","bob","powershell","10.0.0.10","10.0.0.10","powershell","3"],
    ["2026-10-08 01:00:00","host-10","bob","scheduled_task","10.0.0.10","10.0.0.10","schtasks","3"],
    ["2026-10-08 01:05:00","host-10","bob","network_discovery","10.0.0.10","10.0.0.0/24","net.exe","3"],
    ["2026-10-08 01:10:00","host-10","bob","remote_login","10.0.0.10","10.0.0.11","rdp","3"],
    ["2026-10-08 01:15:00","host-11","bob","archive","10.0.0.11","10.0.0.11","7z","4"],
    ["2026-10-08 01:20:00","host-11","bob","upload","10.0.0.11","203.0.113.20","curl","4"],
    ["2026-10-08 01:25:00","host-11","system","ransomware","10.0.0.11","10.0.0.11","cryptolocker","5"],
    ["2026-10-08 01:30:00","host-40","carol","scan","10.0.0.5","10.0.0.40","nmap","4"],
    ["2026-10-08 01:35:00","host-40","carol","login_success","10.0.0.5","10.0.0.40","sshd","4"],
    ["2026-10-08 01:40:00","host-40","carol","powershell","10.0.0.40","10.0.0.40","powershell","4"],
    ["2026-10-08 01:45:00","host-40","carol","credential_dump","10.0.0.40","10.0.0.40","mimikatz","5"],
    ["2026-10-08 01:50:00","host-40","carol","remote_login","10.0.0.40","10.0.0.41","rdp","5"],
    ["2026-10-08 01:55:00","host-41","carol","archive","10.0.0.41","10.0.0.41","7z","4"],
    ["2026-10-08 02:00:00","host-41","carol","upload","10.0.0.41","203.0.113.30","curl","4"],
    ["2026-10-08 02:05:00","host-41","system","ransomware","10.0.0.41","10.0.0.41","cryptolocker","5"],
    ["2026-10-08 02:10:00","host-50","dave","scan","10.0.0.5","10.0.0.50","nmap","3"],
    ["2026-10-08 02:15:00","host-50","dave","login_success","10.0.0.5","10.0.0.50","sshd","3"],
    ["2026-10-08 02:20:00","host-50","dave","network_discovery","10.0.0.50","10.0.0.0/24","net.exe","3"],
    ["2026-10-08 02:25:00","host-50","dave","remote_login","10.0.0.50","10.0.0.51","rdp","3"],
]

doc = SimpleDocTemplate("telemetry_30.pdf", pagesize=A4)
styles = getSampleStyleSheet()
title_style = styles["Heading1"]

def create_pdf():
    elements = []

    elements.append(Paragraph("Debkav – Sample Telemetry (30 events)", title_style))
    elements.append(Spacer(1, 0.25*inch))

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    elements.append(table)
    doc.build(elements)

if __name__ == "__main__":
    create_pdf()
    print("Created telemetry_30.pdf in the current directory.")