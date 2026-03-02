import type { ExtractedPrompt } from '../scanner/extractor.js';

export interface MitigationScore {
  total: number;
  checks: { name: string; present: boolean; reduction: number }[];
}

/**
 * Checks for presence of mitigations in a prompt and returns a risk reduction score.
 */
export function scoreMitigations(prompt: ExtractedPrompt): MitigationScore {
  const text = prompt.text;
  const checks = [
    {
      name: 'System instructions cannot be changed',
      present: /(?:system instructions? (cannot|can't|must not) be (changed|modified|overridden|ignored)|these instructions? (are|remain) (permanent|fixed|immutable)|ignore (any|all) attempts? to (change|modify|override) (your|these) instructions?)/i.test(text),
      reduction: 15,
    },
    {
      name: 'User input delimited and labeled untrusted',
      present: /(?:```[\s\S]*?```|<user>[\s\S]*?<\/user>|\[USER\][\s\S]*?\[\/USER\]|untrusted (user )?(?:content|input)|user.{0,20}(not|never) (an instruction|trusted|a command))/i.test(text),
      reduction: 20,
    },
    {
      name: 'Refuses to reveal system prompt',
      present: /(?:never (reveal|repeat|share|disclose|expose|show|print) (your|the|these) (system |hidden |initial |original )?(?:prompt|instructions?)|do not (reveal|repeat|share|disclose) (this|these|your|the) (system )?(?:prompt|instructions?))/i.test(text),
      reduction: 15,
    },
    {
      name: 'Tool use constrained with allowlist',
      present: /(?:only (use|call|invoke) (the )?(following|listed|allowed|approved)|allowlist|permitted tools?|restricted to.{0,30}(tools?|functions?))/i.test(text),
      reduction: 10,
    },
    {
      name: 'RAG context labeled as untrusted',
      present: /(?:untrusted (external |retrieved )?content|external content.{0,40}(may|might|could) (contain|include) instructions?|do not (follow|execute|treat).{0,30}(retrieved|external|context))/i.test(text),
      reduction: 10,
    },
    {
      // Recognises deliberate input sanitization/escaping applied before interpolation.
      // Reduces the risk weight of injection findings when the developer has wrapped user
      // input in a sanitization function — the clearest signal that the interpolation is
      // intentional and not naively unguarded, which is the primary false-positive scenario.
      name: 'Input sanitization or escaping function present',
      present: /(?:sanitize|sanitise|escape|htmlEscape|DOMPurify\.sanitize|validator\.escape|xss\s*\(|encodeURIComponent|stripTags|purify\.sanitize)\s*\(/i.test(text),
      reduction: 15,
    },
  ];

  const total = checks.reduce((sum, c) => (c.present ? sum + c.reduction : sum), 0);
  return { total, checks };
}
