import type { ScanResult } from "../types";

export function toSarif(result: ScanResult): object {
  return {
    version: "2.1.0",
    $schema:
      "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
    runs: [
      {
        tool: {
          driver: {
            name: "hydra-security",
            informationUri: "https://github.com/hydra-security/hydra-security",
            rules: []
          }
        },
        results: result.findings.map((finding) => ({
          level: finding.severity === "CRITICAL" || finding.severity === "HIGH" ? "error" : "warning",
          ruleId: finding.vuln_class,
          message: { text: finding.title },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: { startLine: finding.line }
              }
            }
          ]
        }))
      }
    ]
  };
}
