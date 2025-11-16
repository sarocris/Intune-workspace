Intune Device Compliance & Automated Remediation Framework

This repository contains the complete automation framework for monitoring and remediating Windows device compliance issues using Intune, Azure Log Analytics, Azure Monitor Alerts, Logic Apps, and Azure Automation Runbooks.

The framework collects device metrics, evaluates compliance (disk space + N-1 patch compliance), and automatically triggers remediation workflows via Azure Automation.

📌 Features
✅ Device Telemetry Collected

Disk space (per drive)

Low disk flag (NeedsDiskCleanup)

Patch compliance (N-1 rule)

Patch remediation flag (NeedsPatchRemediation)

Windows Update status

Defender status + signature age

Pending reboot indicator
(Respects Intune reboot policies — no forced reboots)

✅ Automated Remediation

Low Disk Cleanup

Removes temp data, Windows temp, SoftwareDistribution, Recycle Bin

No impact to user experience

Windows N-1 Patch Compliance

Installs updates older than the current month

Does NOT install the latest “Patch Tuesday” CU

Never forces reboot (Intune owns reboot policy)

✅ Azure Integrated

Log Analytics Workspace ingestion (DCR-based)

KQL-based Azure Monitor alert rules

Logic App orchestration

Hybrid Runbook Worker execution
