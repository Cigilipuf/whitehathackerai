# LLM Models Directory

This directory stores the GGUF model files used by WhiteHatHacker AI's dual-brain engine.

**Models are NOT included in the repository** due to their large size. Download them using the provided script or via LM Studio.

---

## Quick Download

```bash
bash scripts/download_models.sh
```

---

## Required Models

### Primary & Secondary Brain — BaronLLM v2 (Offensive Security)

| Property | Value |
|----------|-------|
| **HuggingFace** | `AlicanKiraz0/BaronLLM-v2-OffensiveSecurity-GGUF` |
| **Base Model** | Qwen3-14B |
| **Parameters** | 15B (dense) |
| **Quantization** | Q8_0 (recommended) |
| **Size** | ~15.7 GB |
| **Context** | 32,768 tokens |
| **VRAM** | 16+ GB recommended (or Apple Silicon unified memory) |
| **Role** | Both primary (/think) and secondary (/no_think) — single model, dual-brain |
| **Training** | 53,202 offensive security examples |
| **Benchmarks** | SecBench MCQ: 86.9% · CS-Eval: 80.93 · SecBench Open: 71.14 |

```bash
# Manual download (Q8_0)
huggingface-cli download AlicanKiraz0/BaronLLM-v2-OffensiveSecurity-GGUF \
    --local-dir ./models/ --include "*q8_0*"
```

### Fallback Brain — DeepHat-V1-7B

| Property | Value |
|----------|-------|
| **HuggingFace** | `Neanderthal/DeepHat-V1-7B-GGUF` |
| **Base Model** | Qwen2.5-Coder-7B |
| **Parameters** | 7.61B (dense) |
| **Quantization** | Q4_K_M |
| **Size** | ~4.68 GB |
| **Context** | 8,192 tokens |
| **VRAM** | 8+ GB recommended |
| **Role** | Emergency fallback — only when both primary & secondary are down |

```bash
# Manual download (Q4_K_M)
huggingface-cli download Neanderthal/DeepHat-V1-7B-GGUF \
    --local-dir ./models/ --include "*q4_k_m*"
```

---

## Configuration

After downloading, set the paths in `.env`:

```bash
WHAI_PRIMARY_MODEL_PATH=models/baronllm-v2-offensivesecurity-q8_0.gguf
WHAI_SECONDARY_MODEL_PATH=models/baronllm-v2-offensivesecurity-q8_0.gguf  # Same model
WHAI_FALLBACK_MODEL_PATH=models/deephat-v1-7b-q4_k_m.gguf
```

Or configure in `config/models.yaml`.

---

## GPU vs CPU

- **GPU (recommended):** Set `WHAI_GPU_LAYERS=-1` to offload all layers to GPU
- **CPU only:** Set `WHAI_GPU_LAYERS=0` (much slower)
- **Partial GPU:** Set `WHAI_GPU_LAYERS=N` where N = number of layers to offload
- **Apple Silicon:** Unified memory means all layers run on Metal GPU by default

Verify with: `bash scripts/health_check.sh`
