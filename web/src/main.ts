/**
 * SlopCrypt Web - Main entry point and UI handlers.
 */

import type { Secret, LMClient } from './types.ts';
import { DEFAULT_PROMPT } from './types.ts';
import { MockLMClient } from './mock-client.ts';
import { WllamaClient, AVAILABLE_MODELS, type ModelConfig } from './wllama-client.ts';
import { generateSecret, encryptSecretBlob, decryptSecretBlob } from './secret.ts';
import { encodeMessage, decodeMessage } from './stego.ts';

// State
let currentSecret: Secret | null = null;
let wllamaClient: WllamaClient | null = null;
let isModelLoading = false;

// DOM Elements
const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

// Tab switching
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    const tabId = (tab as HTMLElement).dataset.tab!;
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    $<HTMLDivElement>(`${tabId}Panel`).classList.add('active');
  });
});

// Initialize model dropdown
function initModelDropdown(): void {
  const select = $<HTMLSelectElement>('modelSelect');
  select.innerHTML = AVAILABLE_MODELS.map(
    (m) => `<option value="${m.id}">${m.name} (${m.size})</option>`
  ).join('');
}

// Call on page load
initModelDropdown();

// Get selected model config
function getSelectedModel(): ModelConfig {
  const select = $<HTMLSelectElement>('modelSelect');
  const modelId = select.value;
  return AVAILABLE_MODELS.find((m) => m.id === modelId) || AVAILABLE_MODELS[0];
}

// Model loading
$<HTMLButtonElement>('loadModelBtn').addEventListener('click', async () => {
  if (isModelLoading) return;

  const btn = $<HTMLButtonElement>('loadModelBtn');
  const status = $<HTMLDivElement>('modelStatus');
  const statusText = $<HTMLSpanElement>('modelStatusText');
  const modelSelect = $<HTMLSelectElement>('modelSelect');
  const selectedModel = getSelectedModel();

  isModelLoading = true;
  btn.disabled = true;
  modelSelect.disabled = true;
  status.className = 'model-status loading';
  statusText.textContent = `Loading ${selectedModel.name} (0%)...`;

  try {
    // Close existing client if loaded
    if (wllamaClient && wllamaClient.loaded) {
      await wllamaClient.close();
    }

    wllamaClient = new WllamaClient(64, selectedModel);
    await wllamaClient.loadModel((progress) => {
      statusText.textContent = `Loading ${selectedModel.name} (${Math.round(progress * 100)}%)...`;
    });

    status.className = 'model-status loaded';
    statusText.textContent = `Model loaded (${selectedModel.name})`;
    btn.textContent = 'Change Model';
    btn.disabled = false;
  } catch (err) {
    status.className = 'model-status';
    statusText.textContent = `Failed to load model: ${err}`;
    btn.disabled = false;
    wllamaClient = null;
  } finally {
    isModelLoading = false;
    modelSelect.disabled = false;
  }
});

// Get current LM client based on checkbox
function getClient(useMock: boolean): LMClient {
  if (useMock) {
    return new MockLMClient(32, 42);
  }
  if (!wllamaClient || !wllamaClient.loaded) {
    throw new Error('Model not loaded. Load the model first or use mock client.');
  }
  return wllamaClient;
}

// Encode button
$<HTMLButtonElement>('encodeBtn').addEventListener('click', async () => {
  const message = $<HTMLTextAreaElement>('encodeMessage').value;
  const prompt = $<HTMLTextAreaElement>('encodePrompt').value || DEFAULT_PROMPT;
  const useMock = $<HTMLInputElement>('encodeMock').checked;
  const progressEl = $<HTMLDivElement>('encodeProgress');
  const progressBar = $<HTMLDivElement>('encodeProgressBar');
  const statusEl = $<HTMLDivElement>('encodeStatus');
  const outputEl = $<HTMLDivElement>('encodeOutput');
  const copyBtn = $<HTMLButtonElement>('copyEncoded');
  const encodeBtn = $<HTMLButtonElement>('encodeBtn');

  if (!message.trim()) {
    statusEl.textContent = 'Please enter a message to encode';
    statusEl.className = 'status error';
    return;
  }

  if (!currentSecret) {
    statusEl.textContent = 'Please generate or load a secret first';
    statusEl.className = 'status error';
    return;
  }

  let client: LMClient;
  try {
    client = getClient(useMock);
  } catch (err) {
    statusEl.textContent = String(err);
    statusEl.className = 'status error';
    return;
  }

  encodeBtn.disabled = true;
  progressEl.style.display = 'block';
  progressBar.style.width = '0%';
  statusEl.textContent = 'Encoding...';
  statusEl.className = 'status';
  outputEl.textContent = '';
  copyBtn.disabled = true;

  try {
    const encoder = new TextEncoder();
    const messageBytes = encoder.encode(message);

    const coverText = await encodeMessage(
      messageBytes,
      currentSecret,
      client,
      prompt,
      true, // compress
      (phase, current, total) => {
        const percent = total > 0 ? Math.round((current / total) * 100) : 0;
        progressBar.style.width = `${percent}%`;
        statusEl.textContent = `${phase}: ${current}/${total}`;
      }
    );

    outputEl.textContent = coverText;
    statusEl.textContent = `Encoded successfully! ${coverText.length} characters`;
    statusEl.className = 'status success';
    copyBtn.disabled = false;
  } catch (err) {
    statusEl.textContent = `Encoding failed: ${err}`;
    statusEl.className = 'status error';
  } finally {
    encodeBtn.disabled = false;
    progressEl.style.display = 'none';
  }
});

// Copy encoded text
$<HTMLButtonElement>('copyEncoded').addEventListener('click', async () => {
  const output = $<HTMLDivElement>('encodeOutput').textContent || '';
  await navigator.clipboard.writeText(output);
  const btn = $<HTMLButtonElement>('copyEncoded');
  const originalText = btn.textContent;
  btn.textContent = 'Copied!';
  setTimeout(() => {
    btn.textContent = originalText;
  }, 1500);
});

// Decode button
$<HTMLButtonElement>('decodeBtn').addEventListener('click', async () => {
  const coverText = $<HTMLTextAreaElement>('decodeCover').value;
  const useMock = $<HTMLInputElement>('decodeMock').checked;
  const progressEl = $<HTMLDivElement>('decodeProgress');
  const progressBar = $<HTMLDivElement>('decodeProgressBar');
  const statusEl = $<HTMLDivElement>('decodeStatus');
  const outputEl = $<HTMLDivElement>('decodeOutput');
  const decodeBtn = $<HTMLButtonElement>('decodeBtn');

  if (!coverText.trim()) {
    statusEl.textContent = 'Please enter cover text to decode';
    statusEl.className = 'status error';
    return;
  }

  if (!currentSecret) {
    statusEl.textContent = 'Please generate or load a secret first';
    statusEl.className = 'status error';
    return;
  }

  let client: LMClient;
  try {
    client = getClient(useMock);
    // Reset wllama context to ensure fresh state for decode
    if (!useMock && wllamaClient) {
      wllamaClient.resetContext();
    }
  } catch (err) {
    statusEl.textContent = String(err);
    statusEl.className = 'status error';
    return;
  }

  decodeBtn.disabled = true;
  progressEl.style.display = 'block';
  progressBar.style.width = '0%';
  statusEl.textContent = 'Decoding...';
  statusEl.className = 'status';
  outputEl.textContent = '';

  try {
    const messageBytes = await decodeMessage(
      coverText,
      currentSecret,
      client,
      '', // Prompt not needed - knock sequence finds payload location
      (phase, current, total) => {
        const percent = total > 0 ? Math.round((current / total) * 100) : 0;
        progressBar.style.width = `${percent}%`;
        statusEl.textContent = `${phase}: ${current}/${total}`;
      }
    );

    const decoder = new TextDecoder();
    const message = decoder.decode(messageBytes);

    outputEl.textContent = message;
    statusEl.textContent = `Decoded successfully! ${messageBytes.length} bytes`;
    statusEl.className = 'status success';
  } catch (err) {
    statusEl.textContent = `Decoding failed: ${err}`;
    statusEl.className = 'status error';
  } finally {
    decodeBtn.disabled = false;
    progressEl.style.display = 'none';
  }
});

// Generate secret
$<HTMLButtonElement>('generateSecretBtn').addEventListener('click', async () => {
  const k = parseInt($<HTMLSelectElement>('secretK').value);
  const preamble = parseInt($<HTMLInputElement>('secretPreamble').value) || 4;
  const suffix = parseInt($<HTMLInputElement>('secretSuffix').value) || 2;
  const entropyThreshold = parseFloat($<HTMLInputElement>('secretEntropyThreshold').value) || 0.0;
  const password = $<HTMLInputElement>('secretPassword').value;
  const notes = $<HTMLInputElement>('secretNotes').value;
  const statusEl = $<HTMLDivElement>('secretStatus');

  if (!password) {
    statusEl.textContent = 'Please enter a password';
    statusEl.className = 'status error';
    return;
  }

  try {
    currentSecret = generateSecret({
      k,
      preambleTokens: preamble,
      suffixTokens: suffix,
      entropyThreshold,
      notes,
    });

    const blob = await encryptSecretBlob(currentSecret, password);
    $<HTMLTextAreaElement>('secretBlob').value = blob;

    updateSecretInfo();

    statusEl.textContent = 'Secret generated! Copy the blob to save it.';
    statusEl.className = 'status success';
    $<HTMLButtonElement>('exportSecretBtn').disabled = false;
  } catch (err) {
    statusEl.textContent = `Failed to generate secret: ${err}`;
    statusEl.className = 'status error';
  }
});

// Load secret
$<HTMLButtonElement>('loadSecretBtn').addEventListener('click', async () => {
  const blob = $<HTMLTextAreaElement>('secretBlob').value.trim();
  const password = $<HTMLInputElement>('loadPassword').value;
  const statusEl = $<HTMLDivElement>('loadStatus');

  if (!blob) {
    statusEl.textContent = 'Please enter a secret blob';
    statusEl.className = 'status error';
    return;
  }

  if (!password) {
    statusEl.textContent = 'Please enter the password';
    statusEl.className = 'status error';
    return;
  }

  try {
    currentSecret = await decryptSecretBlob(blob, password);
    updateSecretInfo();

    statusEl.textContent = 'Secret loaded successfully!';
    statusEl.className = 'status success';
    $<HTMLButtonElement>('exportSecretBtn').disabled = false;
  } catch (err) {
    statusEl.textContent = `Failed to load secret: ${err}`;
    statusEl.className = 'status error';
  }
});

// Export secret
$<HTMLButtonElement>('exportSecretBtn').addEventListener('click', async () => {
  const blob = $<HTMLTextAreaElement>('secretBlob').value;
  if (blob) {
    await navigator.clipboard.writeText(blob);
    const btn = $<HTMLButtonElement>('exportSecretBtn');
    const originalText = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => {
      btn.textContent = originalText;
    }, 1500);
  }
});

// Update secret info display
function updateSecretInfo(): void {
  const card = $<HTMLDivElement>('secretInfoCard');
  const info = $<HTMLDivElement>('secretInfo');

  if (!currentSecret) {
    card.style.display = 'none';
    return;
  }

  card.style.display = 'block';

  const bitsPerToken = Math.log2(currentSecret.k);

  info.innerHTML = `
    <div><dt>Version:</dt><dd>${currentSecret.version}</dd></div>
    <div><dt>K:</dt><dd>${currentSecret.k} (${bitsPerToken} bits/token)</dd></div>
    <div><dt>Knock:</dt><dd>[${currentSecret.knock.join(', ')}]</dd></div>
    <div><dt>Preamble tokens:</dt><dd>${currentSecret.preamble_tokens}</dd></div>
    <div><dt>Suffix tokens:</dt><dd>${currentSecret.suffix_tokens}</dd></div>
    <div><dt>Temperature:</dt><dd>${currentSecret.temperature}</dd></div>
    <div><dt>Entropy threshold:</dt><dd>${currentSecret.entropy_threshold ?? 0}</dd></div>
    <div><dt>Huffman entries:</dt><dd>${currentSecret.huffman_freq ? Object.keys(currentSecret.huffman_freq).length : 'default'}</dd></div>
    ${currentSecret.system_prompt ? `<div><dt>System prompt:</dt><dd>${currentSecret.system_prompt.slice(0, 50)}${currentSecret.system_prompt.length > 50 ? '...' : ''}</dd></div>` : ''}
    ${currentSecret.notes ? `<div><dt>Notes:</dt><dd>${currentSecret.notes}</dd></div>` : ''}
  `;
}

// Initialize: sync mock checkboxes
$<HTMLInputElement>('encodeMock').addEventListener('change', (e) => {
  $<HTMLInputElement>('decodeMock').checked = (e.target as HTMLInputElement).checked;
});

$<HTMLInputElement>('decodeMock').addEventListener('change', (e) => {
  $<HTMLInputElement>('encodeMock').checked = (e.target as HTMLInputElement).checked;
});

// Quick Start: Generate secret (on Encode tab)
$<HTMLButtonElement>('quickGenerateBtn').addEventListener('click', async () => {
  const password = $<HTMLInputElement>('quickPassword').value;
  const successCard = $<HTMLDivElement>('quickSecretSuccess');
  const blobDisplay = $<HTMLDivElement>('quickSecretBlob');

  if (!password) {
    alert('Please enter a password');
    return;
  }

  try {
    currentSecret = generateSecret({
      k: 8,
      preambleTokens: 4,
      suffixTokens: 2,
      entropyThreshold: 0.9,
    });

    const blob = await encryptSecretBlob(currentSecret, password);
    blobDisplay.textContent = blob;
    successCard.classList.remove('hidden');

    // Also update the secrets tab
    $<HTMLTextAreaElement>('secretBlob').value = blob;
    updateSecretInfo();
    $<HTMLButtonElement>('exportSecretBtn').disabled = false;
  } catch (err) {
    alert(`Failed to generate secret: ${err}`);
  }
});

// Quick Start: Copy blob (on Encode tab)
$<HTMLButtonElement>('quickCopyBlob').addEventListener('click', async () => {
  const blob = $<HTMLDivElement>('quickSecretBlob').textContent || '';
  await navigator.clipboard.writeText(blob);
  const btn = $<HTMLButtonElement>('quickCopyBlob');
  const originalText = btn.textContent;
  btn.textContent = 'Copied!';
  setTimeout(() => {
    btn.textContent = originalText;
  }, 1500);
});

// Quick Start: Load secret (on Decode tab)
$<HTMLButtonElement>('quickLoadBtn').addEventListener('click', async () => {
  const blob = $<HTMLTextAreaElement>('quickLoadBlob').value.trim();
  const password = $<HTMLInputElement>('quickLoadPassword').value;
  const statusEl = $<HTMLDivElement>('quickLoadStatus');

  if (!blob) {
    statusEl.textContent = 'Please enter a secret blob';
    statusEl.className = 'status error';
    return;
  }

  if (!password) {
    statusEl.textContent = 'Please enter the password';
    statusEl.className = 'status error';
    return;
  }

  try {
    currentSecret = await decryptSecretBlob(blob, password);
    updateSecretInfo();

    statusEl.textContent = 'Secret loaded! You can now decode messages.';
    statusEl.className = 'status success';

    // Also update the secrets tab
    $<HTMLTextAreaElement>('secretBlob').value = blob;
    $<HTMLButtonElement>('exportSecretBtn').disabled = false;
  } catch (err) {
    statusEl.textContent = `Failed to load secret: ${err}`;
    statusEl.className = 'status error';
  }
});
