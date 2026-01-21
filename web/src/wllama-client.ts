/**
 * wllama client wrapper for browser-based LLM inference.
 * Implements the LMClient interface using wllama's WebAssembly runtime.
 */

import { Wllama } from '@wllama/wllama';
import type { LMClient, TokenProb } from './types.ts';

/**
 * Progress callback for model loading.
 */
export type LoadProgressCallback = (progress: number) => void;

/**
 * wllama client for browser-based LLM inference.
 */
export class WllamaClient implements LMClient {
  private wllama: Wllama | null = null;
  private topK: number;
  private tokenCache: Map<number, string> = new Map();
  private isLoaded: boolean = false;

  constructor(topK: number = 64) {
    this.topK = topK;
  }

  /**
   * Initialize wllama and load model.
   */
  async loadModel(onProgress?: LoadProgressCallback): Promise<void> {
    if (this.isLoaded && this.wllama) {
      return;
    }

    // Initialize wllama with WASM paths from CDN
    this.wllama = new Wllama({
      'single-thread/wllama.wasm':
        'https://cdn.jsdelivr.net/npm/@wllama/wllama@2.3.7/esm/single-thread/wllama.wasm',
      'multi-thread/wllama.wasm':
        'https://cdn.jsdelivr.net/npm/@wllama/wllama@2.3.7/esm/multi-thread/wllama.wasm',
    });

    // Load SmolLM2 model from HuggingFace
    await this.wllama.loadModelFromHF(
      'HuggingFaceTB/SmolLM2-135M-Instruct-GGUF',
      'smollm2-135m-instruct-q8_0.gguf',
      {
        useCache: true, // Cache to OPFS for faster subsequent loads
        progressCallback: (opts) => {
          if (onProgress && opts.total > 0) {
            onProgress(opts.loaded / opts.total);
          }
        },
      }
    );

    this.isLoaded = true;
  }

  /**
   * Check if model is loaded.
   */
  get loaded(): boolean {
    return this.isLoaded;
  }

  /**
   * Get probability distribution over next tokens.
   */
  async getTokenDistribution(context: string): Promise<TokenProb[]> {
    if (!this.wllama || !this.isLoaded) {
      throw new Error('Model not loaded. Call loadModel() first.');
    }

    // Tokenize context
    const tokens = await this.wllama.tokenize(context);
    if (tokens.length === 0) {
      return [];
    }

    // Run inference to get logits
    await this.wllama.samplingInit({});
    await this.wllama.kvClear();

    // Process all tokens to build context
    for (const token of tokens) {
      await this.wllama.decode([token], {});
    }

    // Get logits for top-K tokens
    // Note: wllama returns top candidates via samplingAccept or getLogits
    const logits = await this.wllama.getLogits(this.topK);

    const result: TokenProb[] = [];

    for (const logit of logits) {
      const tokenId = logit.token;
      const prob = logit.p;

      // Get token string (with caching)
      let tokenStr = this.tokenCache.get(tokenId);
      if (tokenStr === undefined) {
        tokenStr = await this.wllama.detokenize([tokenId], true);
        this.tokenCache.set(tokenId, tokenStr);
      }

      // Skip empty tokens (EOS)
      if (!tokenStr) continue;

      result.push({ token: tokenStr, prob });
    }

    // Sort by probability descending, then by token string for stability
    result.sort((a, b) => {
      if (b.prob !== a.prob) return b.prob - a.prob;
      return a.token.localeCompare(b.token);
    });

    return result;
  }

  /**
   * Release model resources.
   */
  async close(): Promise<void> {
    if (this.wllama) {
      await this.wllama.exit();
      this.wllama = null;
      this.isLoaded = false;
      this.tokenCache.clear();
    }
  }
}
