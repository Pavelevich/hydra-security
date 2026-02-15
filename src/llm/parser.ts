import type { Finding, Severity, VulnClass } from "../types";
import { makeFinding } from "../agents/scanner/base";

const VALID_SEVERITIES = new Set<Severity>(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

const VALID_VULN_CLASSES = new Set<VulnClass>([
  "missing_signer_check",
  "missing_has_one",
  "account_type_confusion",
  "arbitrary_cpi",
  "cpi_signer_seed_bypass",
  "cpi_reentrancy",
  "non_canonical_bump",
  "seed_collision",
  "attacker_controlled_seed"
]);

export interface ParseResult {
  findings: Finding[];
  errors: string[];
  rawResponse: string;
}

function extractJsonArray(text: string): string | undefined {
  const fenced = text.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (fenced) {
    return fenced[1].trim();
  }

  const bracketStart = text.indexOf("[");
  const bracketEnd = text.lastIndexOf("]");
  if (bracketStart >= 0 && bracketEnd > bracketStart) {
    return text.slice(bracketStart, bracketEnd + 1);
  }

  return undefined;
}

function isValidSeverity(value: unknown): value is Severity {
  return typeof value === "string" && VALID_SEVERITIES.has(value as Severity);
}

function isValidVulnClass(value: unknown): value is VulnClass {
  return typeof value === "string" && VALID_VULN_CLASSES.has(value as VulnClass);
}

interface RawFinding {
  vuln_class?: unknown;
  severity?: unknown;
  file?: unknown;
  line?: unknown;
  title?: unknown;
  description?: unknown;
  evidence?: unknown;
  confidence?: unknown;
}

function validateAndConvert(
  raw: RawFinding,
  index: number,
  scannerId: string
): { finding?: Finding; error?: string } {
  if (!isValidVulnClass(raw.vuln_class)) {
    return { error: `finding[${index}]: invalid vuln_class "${String(raw.vuln_class)}"` };
  }
  if (!isValidSeverity(raw.severity)) {
    return { error: `finding[${index}]: invalid severity "${String(raw.severity)}"` };
  }
  if (typeof raw.file !== "string" || raw.file.length === 0) {
    return { error: `finding[${index}]: missing or empty file` };
  }
  if (typeof raw.line !== "number" || raw.line < 1) {
    return { error: `finding[${index}]: invalid line number ${String(raw.line)}` };
  }
  if (typeof raw.title !== "string" || raw.title.length === 0) {
    return { error: `finding[${index}]: missing or empty title` };
  }

  const confidence =
    typeof raw.confidence === "number" ? Math.max(0, Math.min(100, Math.round(raw.confidence))) : 50;

  const finding = makeFinding({
    scannerId,
    vulnClass: raw.vuln_class,
    severity: raw.severity,
    confidence,
    file: raw.file,
    line: raw.line,
    title: raw.title,
    description: typeof raw.description === "string" ? raw.description : raw.title,
    evidence: typeof raw.evidence === "string" ? raw.evidence : "LLM-generated finding"
  });

  return { finding };
}

export function parseFindingsResponse(responseText: string, scannerId: string): ParseResult {
  const errors: string[] = [];
  const findings: Finding[] = [];

  const trimmed = responseText.trim();
  if (trimmed === "[]" || trimmed === "") {
    return { findings: [], errors: [], rawResponse: responseText };
  }

  const jsonStr = extractJsonArray(trimmed);
  if (!jsonStr) {
    return {
      findings: [],
      errors: ["Could not extract JSON array from response"],
      rawResponse: responseText
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch (err) {
    return {
      findings: [],
      errors: [`JSON parse error: ${err instanceof Error ? err.message : String(err)}`],
      rawResponse: responseText
    };
  }

  if (!Array.isArray(parsed)) {
    return {
      findings: [],
      errors: ["Response is not a JSON array"],
      rawResponse: responseText
    };
  }

  for (let i = 0; i < parsed.length; i++) {
    const result = validateAndConvert(parsed[i] as RawFinding, i, scannerId);
    if (result.finding) {
      findings.push(result.finding);
    }
    if (result.error) {
      errors.push(result.error);
    }
  }

  return { findings, errors, rawResponse: responseText };
}

export interface GenericParseResult<T> {
  data?: T;
  error?: string;
  rawResponse: string;
}

export function parseJsonResponse<T>(responseText: string): GenericParseResult<T> {
  const trimmed = responseText.trim();

  const fenced = trimmed.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  const jsonStr = fenced ? fenced[1].trim() : trimmed;

  const braceStart = jsonStr.indexOf("{");
  const braceEnd = jsonStr.lastIndexOf("}");
  if (braceStart < 0 || braceEnd <= braceStart) {
    return { error: "No JSON object found in response", rawResponse: responseText };
  }

  try {
    const data = JSON.parse(jsonStr.slice(braceStart, braceEnd + 1)) as T;
    return { data, rawResponse: responseText };
  } catch (err) {
    return {
      error: `JSON parse error: ${err instanceof Error ? err.message : String(err)}`,
      rawResponse: responseText
    };
  }
}
