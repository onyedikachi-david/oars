import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";
import { vault } from "../bridge";
import nodeCrypto from "node:crypto";

// 0. Web Crypto Polyfill for JSDOM
if (typeof window !== "undefined") {
  if (!window.crypto || !window.crypto.subtle) {
    Object.defineProperty(window, "crypto", {
      value: (nodeCrypto as any).webcrypto || nodeCrypto,
      writable: true,
    });
  }
}

// 1. Canvas Mock (Silences JSDOM getContext warnings for XTerm, Sparkline & noVNC)
if (typeof HTMLCanvasElement !== "undefined") {
  const createMockContext = () => ({
    fillRect: vi.fn(),
    clearRect: vi.fn(),
    getImageData: vi.fn(() => ({ data: new Uint8ClampedArray(4) })),
    putImageData: vi.fn(),
    createImageData: vi.fn(() => ({ data: new Uint8ClampedArray(4) })),
    setTransform: vi.fn(),
    resetTransform: vi.fn(),
    drawImage: vi.fn(),
    save: vi.fn(),
    fillText: vi.fn(),
    strokeText: vi.fn(),
    restore: vi.fn(),
    beginPath: vi.fn(),
    moveTo: vi.fn(),
    lineTo: vi.fn(),
    closePath: vi.fn(),
    stroke: vi.fn(),
    translate: vi.fn(),
    scale: vi.fn(),
    rotate: vi.fn(),
    arc: vi.fn(),
    arcTo: vi.fn(),
    ellipse: vi.fn(),
    bezierCurveTo: vi.fn(),
    quadraticCurveTo: vi.fn(),
    fill: vi.fn(),
    measureText: vi.fn(() => ({ width: 10, height: 10 })),
    transform: vi.fn(),
    rect: vi.fn(),
    clip: vi.fn(),
    setLineDash: vi.fn(),
    getLineDash: vi.fn(() => []),
    createLinearGradient: vi.fn(() => ({ addColorStop: vi.fn() })),
    createRadialGradient: vi.fn(() => ({ addColorStop: vi.fn() })),
    createPattern: vi.fn(() => ({})),
    canvas: {},
    fillStyle: "#000",
    strokeStyle: "#000",
    lineWidth: 1,
    lineCap: "butt",
    lineJoin: "miter",
    miterLimit: 10,
    globalAlpha: 1,
    globalCompositeOperation: "source-over",
    shadowBlur: 0,
    shadowColor: "rgba(0, 0, 0, 0)",
    shadowOffsetX: 0,
    shadowOffsetY: 0,
  });

  HTMLCanvasElement.prototype.getContext = vi.fn().mockImplementation((contextId: string) => {
    if (contextId === "2d" || contextId === "webgl" || contextId === "webgl2") {
      return createMockContext();
    }
    return null;
  });
}

// 2. ResizeObserver Mock
if (typeof window !== "undefined" && typeof ResizeObserver === "undefined") {
  (window as any).ResizeObserver = class ResizeObserver {
    observe = vi.fn();
    unobserve = vi.fn();
    disconnect = vi.fn();
  };
}

// 3. IntersectionObserver Mock
if (typeof window !== "undefined" && typeof IntersectionObserver === "undefined") {
  (window as any).IntersectionObserver = class IntersectionObserver {
    observe = vi.fn();
    unobserve = vi.fn();
    disconnect = vi.fn();
    takeRecords = vi.fn(() => []);
  };
}

// 4. matchMedia Mock
if (typeof window !== "undefined" && typeof window.matchMedia === "undefined") {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })) as any;
}

// 5. Scroll & Layout Mocks (enables TanStack Virtualizer in JSDOM)
if (typeof window !== "undefined") {
  window.scrollTo = vi.fn() as any;
  if (typeof Element !== "undefined") {
    Element.prototype.scrollTo = vi.fn();
    Element.prototype.scrollIntoView = vi.fn();
    Element.prototype.getBoundingClientRect = () => ({
      width: 800,
      height: 600,
      top: 0,
      left: 0,
      bottom: 600,
      right: 800,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });
  }
  if (typeof HTMLElement !== "undefined") {
    Object.defineProperty(HTMLElement.prototype, "clientHeight", { configurable: true, value: 600 });
    Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, value: 600 });
    Object.defineProperty(HTMLElement.prototype, "scrollHeight", { configurable: true, value: 6000 });
  }
}

// 6. DataTransfer Mock helper for Drag-and-Drop
if (typeof window !== "undefined" && typeof DataTransfer === "undefined") {
  (window as any).DataTransfer = class DataTransfer {
    data: Record<string, string> = {};
    files: File[] = [];
    dropEffect = "none";
    effectAllowed = "all";
    setData(format: string, data: string) {
      this.data[format] = data;
    }
    getData(format: string) {
      return this.data[format] || "";
    }
    clearData(format?: string) {
      if (format) delete this.data[format];
      else this.data = {};
    }
  };
}

// 7. Global Lifecycle & Cleanup
afterEach(() => {
  cleanup();
  vault.clearCache();
  if (typeof window !== "undefined") {
    delete (window as any).zero;
  }
});
