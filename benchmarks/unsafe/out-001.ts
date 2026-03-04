/**
 * UNSAFE: JSON.parse() on LLM response without schema validation.
 * Expected findings: OUT-001
 */
import OpenAI from 'openai';

const openai = new OpenAI();

export async function extractStructuredData(prompt: string) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      {
        role: 'system',
        content: 'Respond with valid JSON only. No markdown fences.',
      },
      { role: 'user', content: prompt },
    ],
  });

  const content = completion.choices[0].message.content ?? '{}';

  // Vulnerable: parse the model response directly with no schema check.
  // A crafted model response can set arbitrary properties on the result object.
  const result = JSON.parse(content);
  return result.data;
}
