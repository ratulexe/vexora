"use client";

import jsQR from "jsqr";
import { Camera, CircleAlert, ClipboardPaste, ImageUp, LoaderCircle, QrCode, Wifi } from "lucide-react";
import { useEffect, useRef, useState } from "react";

// QR images are decoded here, in the browser. The image never leaves the device;
// only the decoded text is sent for investigation (and Wi-Fi passwords not even that).

const MAX_SIDE = 1600;

const SAMPLES = [
  { label: "Fake refund UPI", src: "/examples/qr-refund-scam.png" },
  { label: "Phishing link", src: "/examples/qr-phishing-link.png" },
  { label: "Shop payment", src: "/examples/qr-shop-payment.png" },
];

export type QrKind = "UPI payment" | "Link" | "Wi-Fi network" | "Text";

export function qrKind(content: string): QrKind {
  const text = content.trim();
  if (/^upi:\/\//i.test(text)) return "UPI payment";
  if (/^wifi:/i.test(text)) return "Wi-Fi network";
  if (/^(https?:\/\/|www\.)\S+$/i.test(text) || /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(text)) return "Link";
  return "Text";
}

interface Props {
  content: string;
  onDecoded: (content: string) => void;
  onSample: (content: string) => void;
  disabled: boolean;
}

export default function QrInput({ content, onDecoded, onSample, disabled }: Props) {
  const [preview, setPreview] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decoding, setDecoding] = useState(false);
  const uploadRef = useRef<HTMLInputElement>(null);
  const cameraRef = useRef<HTMLInputElement>(null);

  async function handleImage(source: Blob | string, fromSample = false) {
    setError(null);
    setDecoding(true);
    try {
      const url = typeof source === "string" ? source : URL.createObjectURL(source);
      setPreview(url);
      const text = await decode(url);
      if (!text) {
        setError("No QR code found. Try a sharper, well-lit image with the whole code visible.");
        onDecoded("");
        return;
      }
      if (fromSample) onSample(text);
      else onDecoded(text);
    } catch {
      setError("That file could not be read as an image.");
    } finally {
      setDecoding(false);
    }
  }

  // Paste a screenshot with Ctrl+V while this tab is open.
  useEffect(() => {
    function onPaste(event: ClipboardEvent) {
      const file = [...(event.clipboardData?.files ?? [])].find((item) => item.type.startsWith("image/"));
      if (file) {
        event.preventDefault();
        void handleImage(file);
      }
    }
    window.addEventListener("paste", onPaste);
    return () => window.removeEventListener("paste", onPaste);
    // handleImage only uses setters and props passed at call time.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const kind = content ? qrKind(content) : null;

  return (
    <div className="qr-input">
      <div
        className="qr-drop"
        onDragOver={(event) => event.preventDefault()}
        onDrop={(event) => {
          event.preventDefault();
          const file = event.dataTransfer.files[0];
          if (file) void handleImage(file);
        }}
      >
        {preview ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={preview} alt="The QR code you added" className="qr-preview" />
        ) : (
          <QrCode size={44} aria-hidden className="qr-placeholder" />
        )}
        <div className="qr-actions">
          <p>Drop a QR code image here, paste a screenshot (Ctrl+V), or:</p>
          <div className="field-row">
            <button type="button" className="button" onClick={() => uploadRef.current?.click()} disabled={disabled}>
              <ImageUp size={16} aria-hidden /> Upload image
            </button>
            <button type="button" className="button" onClick={() => cameraRef.current?.click()} disabled={disabled}>
              <Camera size={16} aria-hidden /> Take photo
            </button>
          </div>
          <input
            ref={uploadRef}
            type="file"
            accept="image/*"
            hidden
            onChange={(event) => event.target.files?.[0] && void handleImage(event.target.files[0])}
          />
          <input
            ref={cameraRef}
            type="file"
            accept="image/*"
            capture="environment"
            hidden
            onChange={(event) => event.target.files?.[0] && void handleImage(event.target.files[0])}
          />
        </div>
      </div>

      {decoding && (
        <p className="note" style={{ marginTop: 12 }}>
          <LoaderCircle size={14} className="spin" aria-hidden style={{ verticalAlign: "-2px" }} /> Reading the QR code
          in your browser...
        </p>
      )}

      {error && (
        <p role="alert" className="alert-error">
          <CircleAlert size={18} aria-hidden /> {error}
        </p>
      )}

      {content && kind && (
        <div className="qr-content">
          <span className="tag">{kind}</span>
          {kind === "Wi-Fi network" ? (
            <p>
              <Wifi size={14} aria-hidden style={{ verticalAlign: "-2px" }} /> This code joins a Wi-Fi network. Its
              password stays on your device.
            </p>
          ) : (
            <code>{content}</code>
          )}
        </div>
      )}

      <div className="examples">
        <span>Try a sample code:</span>
        {SAMPLES.map((sample) => (
          <button
            key={sample.label}
            type="button"
            className="chip"
            onClick={() => void handleImage(sample.src, true)}
            disabled={disabled}
          >
            {sample.label}
          </button>
        ))}
        <ClipboardPaste size={14} aria-hidden style={{ marginLeft: "auto", opacity: 0.6 }} />
      </div>
    </div>
  );
}

async function decode(url: string): Promise<string | null> {
  const image = await loadImage(url);
  // Try the image at a capped size first, then smaller: very large photos can hide the code's pattern.
  for (const limit of [MAX_SIDE, 800]) {
    const scale = Math.min(1, limit / Math.max(image.naturalWidth, image.naturalHeight));
    const width = Math.max(1, Math.round(image.naturalWidth * scale));
    const height = Math.max(1, Math.round(image.naturalHeight * scale));
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) return null;
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, width, height);
    context.drawImage(image, 0, 0, width, height);
    const { data } = context.getImageData(0, 0, width, height);
    const result = jsQR(data, width, height, { inversionAttempts: "attemptBoth" });
    if (result?.data) return result.data;
  }
  return null;
}

function loadImage(url: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = reject;
    image.src = url;
  });
}
