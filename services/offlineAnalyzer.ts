import { AnalysisResult } from "../types";

export function offlineAnalyzeLog(logText: string): AnalysisResult {
  const text = logText.toLowerCase();

  let riskScore = 5;
  let threatDetected = false;

  const recommendations: string[] = [];
  const vectors = {
    persistence: 0,
    lateralMovement: 0,
    exfiltration: 0,
    reconnaissance: 0,
    credentialAccess: 0,
  };

  const addFinding = (score: number, recs: string[], vecUpdates?: Partial<typeof vectors>) => {
    threatDetected = true;
    riskScore = Math.max(riskScore, score);
    recs.forEach((r) => recommendations.push(r));
    if (vecUpdates) {
      Object.assign(vectors, {
        ...vectors,
        ...vecUpdates,
      });
    }
  };

  // Brute force / failed login
  if (text.includes("failed password") || text.includes("authentication failure") || text.includes("failed login")) {
    addFinding(
      65,
      [
        "Block the source IP temporarily (firewall/EDR).",
        "Enable account lockout policy and MFA.",
        "Review authentication logs for successful logins after failures.",
      ],
      { credentialAccess: 80, reconnaissance: 40 }
    );
  }

  // PowerShell encoded / suspicious
  if (text.includes("powershell") && (text.includes("-enc") || text.includes("encodedcommand") || text.includes("hidden"))) {
    addFinding(
      85,
      [
        "Inspect PowerShell ScriptBlock logs (Event ID 4104).",
        "Isolate endpoint if suspicious behavior continues.",
        "Hunt for download/execute activity and persistence mechanisms.",
      ],
      { persistence: 60, credentialAccess: 50, reconnaissance: 50 }
    );
  }

  // Reverse shell / C2 port
  if (text.includes("4444") || text.includes("1337")) {
    addFinding(
      95,
      [
        "Immediately isolate the host from the network.",
        "Block destination IP/port at firewall.",
        "Collect memory dump and process tree for investigation.",
      ],
      { lateralMovement: 70, exfiltration: 60, persistence: 50 }
    );
  }

  // SQL injection
  if (text.includes("union select") || text.includes("or '1'='1") || text.includes("sql injection")) {
    addFinding(
      80,
      [
        "Check web server logs for repeated malicious requests.",
        "Enable WAF rules and input validation.",
        "Review database logs for suspicious queries or data access.",
      ],
      { reconnaissance: 70, exfiltration: 50 }
    );
  }

  // Mimikatz / credential dumping
  if (text.includes("mimikatz") || text.includes("sekurlsa::logonpasswords")) {
    addFinding(
      98,
      [
        "Isolate endpoint immediately.",
        "Reset compromised credentials and enforce MFA.",
        "Hunt for lateral movement using new credentials.",
      ],
      { credentialAccess: 95, lateralMovement: 80, persistence: 50 }
    );
  }

  if (
  text.includes("vssadmin delete shadows") ||
  text.includes(".locked") ||
  text.includes("files renamed") ||
  text.includes("encryptor.exe") ||
  text.includes("shadow copies deletion")
) {
  addFinding(
    99,
    [
      "Isolate the host immediately to stop encryption spread.",
      "Kill the suspicious encryption process and collect evidence.",
      "Restore from backups and check for lateral movement.",
      "Disable SMB shares temporarily if spreading is suspected."
    ],
    { persistence: 70, lateralMovement: 60, exfiltration: 40, reconnaissance: 30, credentialAccess: 40 }
  );
}

if (
  text.includes("action=drop") &&
  (text.includes("dpt=22") || text.includes("dpt=80") || text.includes("dpt=443") || text.includes("dpt=3389") || text.includes("dpt=445"))
) {
  addFinding(
    60,
    [
      "Block or rate-limit the scanning source IP.",
      "Check IDS/Firewall logs for scan patterns (SYN scan).",
      "Verify if the source host is compromised or running scanning tools."
    ],
    { reconnaissance: 85, lateralMovement: 30 }
  );
}

if (
  text.includes("unusual outbound traffic") ||
  text.includes("transferred") ||
  text.includes("gb in") ||
  text.includes("data exfiltration")
) {
  addFinding(
    88,
    [
      "Verify if the data transfer is legitimate (business need).",
      "Check destination reputation and TLS SNI/domain logs.",
      "Inspect user activity and files accessed before transfer.",
      "Enable DLP rules and alert on large outbound transfers."
    ],
    { exfiltration: 90, reconnaissance: 30, credentialAccess: 30 }
  );
}



  const explanation = threatDetected
    ? `Offline SOC analysis detected suspicious indicators in the logs. Risk Score: ${riskScore}/100.`
    : "No clear indicators of compromise detected in offline analysis.";

  return {
    riskScore,
    threatDetected,
    explanation,
    recommendations: [...new Set(recommendations)],
    threatVectors: vectors,
  };
}
