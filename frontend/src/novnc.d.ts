declare module "@novnc/novnc" {
  export interface RFBOptions {
    credentials?: Record<string, string>;
    wsProtocols?: string[];
  }

  export default class RFB extends EventTarget {
    constructor(target: HTMLElement, url: string, options?: RFBOptions);
    scaleViewport: boolean;
    resizeSession: boolean;
    disconnect(): void;
    sendCredentials(credentials: Record<string, string>): void;
    sendCtrlAltDel(): void;
    clipboardPasteFrom(text: string): void;
  }
}
