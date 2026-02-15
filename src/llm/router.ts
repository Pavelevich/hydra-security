export type AgentTask =
  | "threat-model"
  | "scanner"
  | "red-team"
  | "blue-team"
  | "judge"
  | "patch"
  | "review";

export interface ModelRoute {
  primary: string;
  fallbacks: string[];
}

const MODELS = {
  opus: "claude-opus-4-6-20250605",
  sonnet: "claude-sonnet-4-5-20250929",
  haiku: "claude-haiku-4-5-20251001"
} as const;

const routes: Record<AgentTask, ModelRoute> = {
  "threat-model": { primary: MODELS.opus, fallbacks: [MODELS.sonnet] },
  judge: { primary: MODELS.opus, fallbacks: [MODELS.sonnet] },
  scanner: { primary: MODELS.haiku, fallbacks: [MODELS.sonnet] },
  review: { primary: MODELS.haiku, fallbacks: [MODELS.sonnet] },
  "red-team": { primary: MODELS.sonnet, fallbacks: [MODELS.opus] },
  "blue-team": { primary: MODELS.sonnet, fallbacks: [MODELS.opus] },
  patch: { primary: MODELS.sonnet, fallbacks: [MODELS.opus] }
};

export function routeModel(task: AgentTask): string {
  return routes[task].primary;
}

export function routeModelWithFallbacks(task: AgentTask): ModelRoute {
  return routes[task];
}

export function allModelIds(): string[] {
  return Object.values(MODELS);
}
