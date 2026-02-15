export type AgentTask =
  | "threat-model"
  | "scanner"
  | "red-team"
  | "blue-team"
  | "judge"
  | "patch"
  | "review";

export function routeModel(task: AgentTask): string {
  switch (task) {
    case "threat-model":
    case "judge":
      return "claude-opus";
    case "scanner":
    case "review":
      return "claude-haiku";
    case "red-team":
    case "blue-team":
    case "patch":
      return "claude-sonnet";
    default:
      return "claude-sonnet";
  }
}
