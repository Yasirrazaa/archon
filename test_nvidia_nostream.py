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
      stream=False
    )
    print("Content:")
    print(completion.choices[0].message.content)
except Exception as e:
    print(f"Error: {e}")
