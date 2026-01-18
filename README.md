# security-posture-analyzer
Security posture anomaly detection using Python automation, Nmap, endpoint logs, and analytics dashboards.
<br>
Author - Shalini Dey
//scripts/asset_port_analysis.py
import pandas as pd

scan_df = pd.read_csv("../data/scan_results.csv")

scan_df["Open_Ports_Count"] = scan_df["Open_Ports"].apply(
    lambda x: len(str(x).split(","))
)

vulnerable_assets = scan_df[scan_df["Open_Ports_Count"] > 5]

print("Vulnerable Assets:")
print(vulnerable_assets)

vulnerable_assets.to_csv("../output/vulnerable_assets.csv", index=False)
//scripts/security_posture_check.py
import pandas as pd

posture_df = pd.read_excel("../data/Posture-Asset.xlsx")

weak_assets = posture_df[
    (posture_df["IPS Status"] == "Disabled") |
    (posture_df["UBA Status"] == "Disabled") |
    (posture_df["Malware Detected"] == "Yes")
]

print("Assets with Weak Security Posture:")
print(weak_assets)

weak_assets.to_csv("../output/weak_posture_assets.csv", index=False)
//scripts/url_reputation_analysis.py
import pandas as pd

url_df = pd.read_excel("../data/URLReputation.xlsx")

risky_urls = url_df[
    (url_df["Reputation"].isin(["Malicious", "Suspicious"]))
]

print("Risky URLs:")
print(risky_urls)

risky_urls.to_csv("../output/risky_urls.csv", index=False)
//scripts/incident_correlation.py
import pandas as pd

scan_df = pd.read_csv("../data/scan_results.csv")
posture_df = pd.read_excel("../data/Posture-Asset.xlsx")
url_df = pd.read_excel("../data/URLReputation.xlsx")

risky_urls = url_df[url_df["Reputation"].isin(["Malicious", "Suspicious"])]

incident_report = posture_df.merge(risky_urls, on="User ID", how="inner")
incident_report = incident_report.merge(scan_df, on="Hostname", how="inner")

print("Incident Report Generated")
print(incident_report)

incident_report.to_csv("../output/incident_summary.csv", index=False)
//scripts/export_for_powerbi.py
print("Incident summary is ready for Power BI visualization.")


