"""Chinese AI framework detection signatures.

Provides detection signatures for major Chinese AI/LLM frameworks including:
- Qwen (Alibaba)
- Ernie (Baidu)
- GLM (Zhipu AI)
- Kimi (Moonshot AI)
- MiniMax
- DeepSeek
"""

from .index import ChineseSignatureLoader

__all__ = ["ChineseSignatureLoader"]