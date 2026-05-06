export type RuleType = "bash" | "pkg-install" | "destructive" | "secret-read" | "net-egress-url" | "custom";

export interface AddRuleInitialPreset {
  ruleType?: RuleType;
  id?: string;
  tool?: string;
  commandRegexes?: string;
  pathRegexes?: string;
  urlRegexes?: string;
  action?: "deny" | "allow";
  mode?: "inherit" | "monitor" | "enforce";
}
