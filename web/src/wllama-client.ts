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
 *
 * Supports incremental inference: if you call getTokenDistribution with a context
 * that extends the previous context, only the new tokens are decoded (O(1) per token
 * instead of O(N) for full re-decode).
 */
export class WllamaClient implements LMClient {
  private wllama: Wllama | null = null;
  private topK: number;
  private tokenCache: Map<number, string> = new Map();
  private isLoaded: boolean = false;

  // Incremental inference state
  private lastContext: string = '';
  private lastTokens: number[] = [];

  constructor(topK: number = 64) {
    this.topK = topK;
  }

  /**
   * Create a fresh Wllama instance with CDN WASM paths.
   */
  private createWllamaInstance(): Wllama {
    return new Wllama({
      'single-thread/wllama.wasm':
        'https://cdn.jsdelivr.net/npm/@wllama/wllama@2.3.7/esm/single-thread/wllama.wasm',
      'multi-thread/wllama.wasm':
        'https://cdn.jsdelivr.net/npm/@wllama/wllama@2.3.7/esm/multi-thread/wllama.wasm',
    });
  }

  /**
   * Initialize wllama and load model.
   */
  async loadModel(onProgress?: LoadProgressCallback): Promise<void> {
    if (this.isLoaded && this.wllama) {
      return;
    }

    // Try loading with cache first
    try {
      this.wllama = this.createWllamaInstance();
      await this.loadModelWithOptions(onProgress, true);
      this.isLoaded = true;
      return;
    } catch (err) {
      console.warn('Cached model load failed, retrying without cache:', err);
      // Clean up failed instance
      if (this.wllama) {
        try {
          await this.wllama.exit();
        } catch {
          // Ignore cleanup errors
        }
        this.wllama = null;
      }
    }

    // Retry with fresh instance and no cache
    this.wllama = this.createWllamaInstance();
    await this.loadModelWithOptions(onProgress, false);
    this.isLoaded = true;
  }

  /**
   * Load model with specified cache option.
   */
  private async loadModelWithOptions(
    onProgress?: LoadProgressCallback,
    useCache: boolean = true
  ): Promise<void> {
    if (!this.wllama) throw new Error('Wllama not initialized');

    // Detect available threads (use navigator.hardwareConcurrency, cap at 4 for WASM)
    const maxThreads = Math.min(navigator.hardwareConcurrency || 4, 4);

    await this.wllama.loadModelFromHF(
      'unsloth/SmolLM2-135M-Instruct-GGUF',
      'SmolLM2-135M-Instruct-Q8_0.gguf',
      {
        n_threads: maxThreads,
        useCache,
        progressCallback: (opts) => {
          if (onProgress && opts.total > 0) {
            onProgress(opts.loaded / opts.total);
          }
        },
      }
    );
  }

  /**
   * Check if model is loaded.
   */
  get loaded(): boolean {
    return this.isLoaded;
  }

  /**
   * Get probability distribution over next tokens.
   *
   * Supports incremental inference: if the new context extends the previous one,
   * only the new tokens are decoded (massive speedup for sequential generation).
   */
  async getTokenDistribution(context: string): Promise<TokenProb[]> {
    if (!this.wllama || !this.isLoaded) {
      throw new Error('Model not loaded. Call loadModel() first.');
    }

    // Tokenize the full context
    const tokens = await this.wllama.tokenize(context);
    if (tokens.length === 0) {
      return [];
    }

    // Check if this context extends the previous one (incremental inference)
    const isIncremental =
      context.startsWith(this.lastContext) &&
      this.lastContext.length > 0 &&
      this.lastTokens.length > 0;

    if (isIncremental) {
      // Only decode the new tokens (O(delta) instead of O(N))
      const newTokens = tokens.slice(this.lastTokens.length);
      if (newTokens.length > 0) {
        await this.wllama.decode(newTokens, {});
      }
    } else {
      // Full context switch - need to re-decode everything
      await this.wllama.samplingInit({});
      await this.wllama.kvClear();
      await this.wllama.decode(tokens, {});
    }

    // Update state for next call
    this.lastContext = context;
    this.lastTokens = tokens;

    // Get logits for top-K tokens
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
   * Reset the incremental inference state.
   * Call this when switching to a completely different context.
   */
  resetContext(): void {
    this.lastContext = '';
    this.lastTokens = [];
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
      this.resetContext();
    }
  }
}
