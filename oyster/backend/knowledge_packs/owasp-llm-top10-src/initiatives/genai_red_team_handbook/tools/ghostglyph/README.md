<!-- source: https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/99f4395589bdbd120ae961f9cd179e79d7f9b27f/initiatives/genai_red_team_handbook/tools/ghostglyph/README.md -->
# ghostglyph

![ghost glyph logo](./ghostglyph.png)

A tool to assist with ascii smuggling attacks against generative AI based systems.

Usage:
1. Run `uv run src/app.py`
2. Open the webpage in a browser
3. Enter the text you want to encode and select the type of encoding to use
4. Copy the encoded text and use it in your prompt injection payloads


# Reference Documentation

* [Defending LLM Applications Against Unicode Character Smuggling](https://aws.amazon.com/blogs/security/defending-llm-applications-against-unicode-character-smuggling/) - by Amazon
* [ASCII Smuggler Tool](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/) - by EmbraceTheRed