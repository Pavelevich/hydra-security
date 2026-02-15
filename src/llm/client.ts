export interface LlmMessage {
  role: "user" | "assistant";
  content: string;
}

export interface LlmRequest {
  model: string;
  system?: string;
  messages: LlmMessage[];
  max_tokens: number;
  temperature?: number;
  stop_sequences?: string[];
}

export interface LlmResponse {
  id: string;
  model: string;
  content: string;
  input_tokens: number;
  output_tokens: number;
  stop_reason: string;
}

export interface LlmStreamDelta {
  type: "text" | "stop" | "error";
  text?: string;
  error?: string;
  stop_reason?: string;
}

export interface LlmClientOptions {
  apiKey?: string;
  baseUrl?: string;
  maxRetries?: number;
  requestTimeoutMs?: number;
  fallbackModels?: string[];
}

const DEFAULT_BASE_URL = "https://api.anthropic.com";
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_REQUEST_TIMEOUT_MS = 120_000;
const API_VERSION = "2023-06-01";
const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 30_000;
const JITTER_FACTOR = 0.25;

function envString(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

function addJitter(delayMs: number): number {
  const jitter = delayMs * JITTER_FACTOR * (Math.random() * 2 - 1);
  return Math.max(0, delayMs + jitter);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status === 500 || status === 502 || status === 503 || status === 529;
}

function parseRetryAfterMs(headers: Headers): number | undefined {
  const retryAfter = headers.get("retry-after");
  if (!retryAfter) return undefined;
  const seconds = Number(retryAfter);
  if (Number.isFinite(seconds) && seconds > 0) {
    return seconds * 1_000;
  }
  return undefined;
}

export class LlmApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly body?: string
  ) {
    super(message);
  }
}

export class LlmClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly maxRetries: number;
  private readonly requestTimeoutMs: number;
  private readonly fallbackModels: string[];

  constructor(options: LlmClientOptions = {}) {
    this.apiKey = options.apiKey ?? envString("ANTHROPIC_API_KEY", "");
    this.baseUrl = options.baseUrl ?? envString("HYDRA_LLM_BASE_URL", DEFAULT_BASE_URL);
    this.maxRetries = options.maxRetries ?? envInt("HYDRA_LLM_MAX_RETRIES", DEFAULT_MAX_RETRIES);
    this.requestTimeoutMs =
      options.requestTimeoutMs ?? envInt("HYDRA_LLM_TIMEOUT_MS", DEFAULT_REQUEST_TIMEOUT_MS);
    this.fallbackModels = options.fallbackModels ?? [];
  }

  async createMessage(request: LlmRequest): Promise<LlmResponse> {
    const modelsToTry = [request.model, ...this.fallbackModels.filter((m) => m !== request.model)];

    let lastError: Error | undefined;
    for (const model of modelsToTry) {
      try {
        return await this.executeWithRetry({ ...request, model });
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (error instanceof LlmApiError && error.status === 401) {
          throw error;
        }
      }
    }

    throw lastError ?? new Error("All models exhausted");
  }

  async *streamMessage(request: LlmRequest): AsyncGenerator<LlmStreamDelta, LlmResponse> {
    this.requireApiKey();

    const body = this.buildRequestBody(request, true);
    const response = await this.fetchWithTimeout(body);

    if (!response.ok) {
      const errorBody = await response.text();
      throw new LlmApiError(
        `API error ${response.status}: ${errorBody}`,
        response.status,
        errorBody
      );
    }

    if (!response.body) {
      throw new Error("Streaming response has no body");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let fullContent = "";
    let responseId = "";
    let responseModel = request.model;
    let inputTokens = 0;
    let outputTokens = 0;
    let stopReason = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const data = line.slice(6).trim();
          if (data === "[DONE]") continue;

          let event: Record<string, unknown>;
          try {
            event = JSON.parse(data) as Record<string, unknown>;
          } catch {
            continue;
          }

          const eventType = event.type as string;

          if (eventType === "message_start") {
            const message = event.message as Record<string, unknown>;
            responseId = (message.id as string) ?? "";
            responseModel = (message.model as string) ?? request.model;
            const usage = message.usage as Record<string, number> | undefined;
            if (usage) {
              inputTokens = usage.input_tokens ?? 0;
            }
          } else if (eventType === "content_block_delta") {
            const delta = event.delta as Record<string, unknown>;
            if (delta.type === "text_delta") {
              const text = delta.text as string;
              fullContent += text;
              yield { type: "text", text };
            }
          } else if (eventType === "message_delta") {
            const delta = event.delta as Record<string, unknown>;
            stopReason = (delta.stop_reason as string) ?? "";
            const usage = event.usage as Record<string, number> | undefined;
            if (usage) {
              outputTokens = usage.output_tokens ?? 0;
            }
          } else if (eventType === "error") {
            const errorObj = event.error as Record<string, unknown>;
            yield { type: "error", error: (errorObj.message as string) ?? "stream_error" };
          }
        }
      }
    } finally {
      reader.releaseLock();
    }

    yield { type: "stop", stop_reason: stopReason };

    return {
      id: responseId,
      model: responseModel,
      content: fullContent,
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      stop_reason: stopReason
    };
  }

  private async executeWithRetry(request: LlmRequest): Promise<LlmResponse> {
    this.requireApiKey();

    let attempt = 0;
    let backoffMs = INITIAL_BACKOFF_MS;

    while (true) {
      const body = this.buildRequestBody(request, false);
      let response: Response;

      try {
        response = await this.fetchWithTimeout(body);
      } catch (error) {
        if (attempt >= this.maxRetries) throw error;
        attempt++;
        backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
        await sleep(addJitter(backoffMs));
        continue;
      }

      if (response.ok) {
        return this.parseResponse(await response.json());
      }

      const responseBody = await response.text();

      if (!isRetryableStatus(response.status) || attempt >= this.maxRetries) {
        throw new LlmApiError(
          `API error ${response.status}: ${responseBody}`,
          response.status,
          responseBody
        );
      }

      const retryAfter = parseRetryAfterMs(response.headers);
      const waitMs = retryAfter ?? addJitter(backoffMs);
      attempt++;
      backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
      await sleep(waitMs);
    }
  }

  private buildRequestBody(
    request: LlmRequest,
    stream: boolean
  ): Record<string, unknown> {
    const body: Record<string, unknown> = {
      model: request.model,
      max_tokens: request.max_tokens,
      messages: request.messages,
      stream
    };
    if (request.system) {
      body.system = request.system;
    }
    if (request.temperature !== undefined) {
      body.temperature = request.temperature;
    }
    if (request.stop_sequences && request.stop_sequences.length > 0) {
      body.stop_sequences = request.stop_sequences;
    }
    return body;
  }

  private async fetchWithTimeout(body: Record<string, unknown>): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.requestTimeoutMs);

    try {
      return await fetch(`${this.baseUrl}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": this.apiKey,
          "anthropic-version": API_VERSION
        },
        body: JSON.stringify(body),
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private parseResponse(raw: unknown): LlmResponse {
    const obj = raw as Record<string, unknown>;
    const content = obj.content as Array<Record<string, unknown>>;
    const textBlock = content?.find((block) => block.type === "text");
    const usage = obj.usage as Record<string, number> | undefined;

    return {
      id: (obj.id as string) ?? "",
      model: (obj.model as string) ?? "",
      content: (textBlock?.text as string) ?? "",
      input_tokens: usage?.input_tokens ?? 0,
      output_tokens: usage?.output_tokens ?? 0,
      stop_reason: (obj.stop_reason as string) ?? ""
    };
  }

  private requireApiKey(): void {
    if (!this.apiKey) {
      throw new Error(
        "ANTHROPIC_API_KEY is not set. Set the environment variable or pass apiKey to LlmClient."
      );
    }
  }
}

let defaultClient: LlmClient | undefined;

export function getDefaultClient(): LlmClient {
  if (!defaultClient) {
    defaultClient = new LlmClient();
  }
  return defaultClient;
}
