# FreedomSearch

Empower your AI models with ethical, open-source web intelligence.

FreedomSearch is a Python library designed to enhance AI prompts and queries with real-time web information. It respects fair use principles and leverages multiple search engines to provide diverse, up-to-date context for your language models.

Key Features:
- 🌐 Multi-engine support (DuckDuckGo, Google, and expandable)
- 🔍 Efficient caching and rate limiting
- 🧠 Smart text preprocessing and formatting for LLMs
- 🛡️ Built with privacy and fair use in mind
- 🔧 Easy to integrate and extend

Whether you're building the next-gen chatbot or fine-tuning language models, FreedomSearch provides the tools to ethically augment your AI's knowledge base.

## Quick Start

```python
from freedom_search import InternetSearchEnhancer

enhancer = InternetSearchEnhancer('duckduckgo')
original_prompt = "Explain quantum computing"
enhanced_prompt = enhancer.enhance_llm_input(original_prompt, "recent quantum computing breakthroughs")

print(enhanced_prompt)
```

Contribute to FreedomSearch and help shape the future of ethical AI augmentation!
```

This description:

1. Starts with a catchy tagline that encapsulates the library's purpose and ethical stance.
2. Briefly explains what FreedomSearch does and its target use case.
3. Lists key features using emojis for visual appeal and quick scanning.
4. Includes a short pitch for potential users and contributors.
5. Provides a quick start code snippet to show how easy it is to use.
6. Ends with a call-to-action for contributions, emphasizing the open-source nature of the project.

