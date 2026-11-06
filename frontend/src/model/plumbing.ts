/*
 * Hints for routes that look like AWS-managed plumbing (Control Tower, AFT, IAM Identity Center ...). A hint is
 * only a suggestion shown next to the route: nothing is hidden until the user marks the route expected (D-58).
 * Matching is on the whole ARN (role path and name), never on a last segment taken apart (F-039).
 */
const RULES: readonly [RegExp, string][] = [
  [/:role\/aws-reserved\/sso\.amazonaws\.com\//, 'IAM Identity Center permission set'],
  [/:saml-provider\/AWSSSO_/, 'IAM Identity Center'],
  [/:role\/(?:AWSControlTowerExecution|aws-controltower-[A-Za-z]+)$/, 'AWS Control Tower'],
  [/:role\/AWSAFT[A-Za-z-]*$/, 'Account Factory for Terraform'],
  [/:role\/OrganizationAccountAccessRole$/, 'AWS Organizations access role'],
  [/:role\/aws-service-role\//, 'service-linked role'],
  [/:role\/(?:stacksets-exec-[0-9a-f]+|AWSCloudFormationStackSetExecutionRole)$/, 'CloudFormation StackSets'],
];

export function plumbingOf(id: string): string | null {
  for (const [re, label] of RULES) if (re.test(id)) return label;
  return null;
}

/** The kinds of AWS plumbing a route goes through (empty when none): what the hint chip says. */
export function plumbingHint(path: readonly string[]): string[] {
  const out: string[] = [];
  for (const id of path) {
    const label = plumbingOf(id);
    if (label && !out.includes(label)) out.push(label);
  }
  return out;
}
