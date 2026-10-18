"""Local media runtime helpers (all on-device, no cloud):

- ``vision``     — Ollama vision-language model adapter (image + video frames)
- ``ocr``        — optional Tesseract OCR (falls back to VLM text reading)
- ``transcribe`` — faster-whisper local speech-to-text
- ``video_probe``— ffmpeg/ffprobe subprocess helpers (metadata/thumbnail/frames/audio)
- ``redact``     — secret redaction for previews/logs
"""
