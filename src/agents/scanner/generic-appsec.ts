import path from "node:path";
import { promises as fs } from "node:fs";
import { listFilesRecursive, scanFileWithPatterns, type PatternRule, type Scanner } from "./base";

const SOURCE_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".py",
  ".go",
  ".java",
  ".rb",
  ".php",
  ".cs",
  ".rs",
  ".swift",
  ".kt",
  ".scala",
  ".sh",
  ".bash",
  ".zsh"
]);

function isSourceFile(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  if (base === ".env" || base.endsWith(".env")) {
    return true;
  }
  return SOURCE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

const patternRules: PatternRule[] = [
  {
    vulnClass: "hardcoded_secret",
    severity: "HIGH",
    confidence: 74,
    title: "Potential hardcoded secret",
    description:
      "Credential-like value appears hardcoded in source. Move secrets to a secure secret manager or environment variables.",
    pattern:
      /\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b.{0,40}[:=]\s*["'][A-Za-z0-9+/_=-]{12,}["']/i,
    mitigations: [/\b(process\.env|System\.getenv|os\.environ|getenv\(|ENV\[)\b/i]
  },
  {
    vulnClass: "command_injection",
    severity: "CRITICAL",
    confidence: 72,
    title: "Potential command injection",
    description:
      "Shell/process execution appears to include concatenated or interpolated input. Use argument arrays and strict input allowlists.",
    pattern:
      /\b(exec|execSync|spawn|spawnSync|system|popen|Runtime\.getRuntime\(\)\.exec|subprocess\.(run|Popen))\b.*(\+|\$\{|%s|format\()/i,
    mitigations: [
      /\b(spawn|spawnSync)\s*\(\s*["'][^"']+["']\s*,\s*\[/i,
      /\bshell\s*=\s*False\b/i
    ]
  },
  {
    vulnClass: "sql_injection",
    severity: "HIGH",
    confidence: 67,
    title: "Potential SQL injection",
    description:
      "SQL statement appears built via string interpolation/concatenation. Use parameterized queries or prepared statements.",
    pattern:
      /\b(SELECT|INSERT|UPDATE|DELETE)\b.{0,120}(\+|\$\{|format\(|f["']).{0,120}\b(WHERE|VALUES|SET)\b/i,
    mitigations: [
      /\b(prepare|prepared|parameterized|bindParam|bindValue)\b/i,
      /\b(query|execute)\s*\([^,]+,\s*[\[\(]/i
    ]
  },
  {
    vulnClass: "xss",
    severity: "HIGH",
    confidence: 64,
    title: "Potential XSS sink usage",
    description:
      "Potential unsafe HTML sink assignment detected. Prefer safe text APIs or sanitize untrusted input before rendering.",
    pattern: /\b(innerHTML|outerHTML|document\.write)\b\s*[\(\=]/,
    mitigations: [/\b(DOMPurify|sanitizeHtml|xss\.filter|escapeHtml)\b/i]
  },
  {
    vulnClass: "insecure_deserialization",
    severity: "HIGH",
    confidence: 68,
    title: "Potential insecure deserialization",
    description:
      "Unsafe deserialization primitive detected. Avoid deserializing untrusted data or enforce strict schema and allowlists.",
    pattern: /\b(pickle\.loads|yaml\.load\s*\(|BinaryFormatter\.Deserialize|ObjectInputStream|unserialize\s*\(|Marshal\.load)\b/
  }
];

export const genericAppSecScanner: Scanner = {
  id: "scanner.generic.appsec",
  async scan(rootPath: string) {
    const files = await listFilesRecursive(rootPath, isSourceFile);
    const findings = [];

    for (const filePath of files) {
      let content: string;
      try {
        content = await fs.readFile(filePath, "utf8");
      } catch {
        continue;
      }
      findings.push(...scanFileWithPatterns(this.id, filePath, content, patternRules));
    }

    return findings;
  }
};
