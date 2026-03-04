/**
 * SAFE: LLM output consumed with schema validation and HTML sanitization.
 *
 * Safe because:
 *   - JSON.parse() is guarded by Zod schema validation before use
 *   - Markdown is sanitized with DOMPurify before rendering
 *
 * Expected findings: NONE
 */
import OpenAI from 'openai';
import { z } from 'zod';
import DOMPurify from 'dompurify';
import { marked } from 'marked';

const openai = new OpenAI();

const ResponseSchema = z.object({
  answer: z.string(),
  confidence: z.number().min(0).max(1),
  sources: z.array(z.string()),
});

export async function safeJsonConsumer(prompt: string) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }],
  });

  const raw = completion.choices[0].message.content ?? '{}';

  // Safe: parse then immediately validate with Zod before accessing any properties
  const parsed = ResponseSchema.parse(JSON.parse(raw));
  return parsed;
}

export async function safeMarkdownConsumer(prompt: string): Promise<string> {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }],
  });

  const output = completion.choices[0].message.content ?? '';

  // Safe: sanitize with DOMPurify before rendering
  const dirty = marked.parse(output) as string;
  return DOMPurify.sanitize(dirty, { ALLOWED_TAGS: ['p', 'strong', 'em', 'ul', 'li'] });
}
