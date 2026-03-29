from openai import OpenAI
import os

client = OpenAI(
  base_url = "https://integrate.api.nvidia.com/v1",
  api_key = "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"
)

try:
    completion = client.chat.completions.create(
      model="openai/gpt-oss-20b",
      messages=[{"role":"user","content":"Hello, what are you?"}],
      temperature=1,
      top_p=1,
      max_tokens=4096,
      stream=True
    )

    for chunk in completion:
      if not getattr(chunk, "choices", None):
        continue
      reasoning = getattr(chunk.choices[0].delta, "reasoning_content", None)
      if reasoning:
        print(reasoning, end="")
      if chunk.choices and chunk.choices[0].delta.content is not None:
        print(chunk.choices[0].delta.content, end="")
except Exception as e:
    print(f"Error: {e}")
