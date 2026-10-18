"use client";

import { useState } from "react";
import {
  Copy,
  Check,
  RefreshCw,
  FileText,
  Sparkles,
  Bug,
  ClipboardCheck,
  Pin,
  Bookmark,
  ThumbsUp,
  ThumbsDown,
} from "lucide-react";
import { type Message } from "@/types/chat";

export type MessageAction =
  | "regenerate"
  | "summarize"
  | "explain"
  | "createFinding"
  | "addToReport"
  | "pin"
  | "bookmark"
  /** Was this answer good? The signal Oyster never collected — without it,
   *  training treats every past reply as worth imitating, mistakes included. */
  | "rateUp"
  | "rateDown";

interface MessageToolbarProps {
  message: Message;
  onAction: (action: MessageAction, message: Message) => void;
}

export function MessageToolbar({ message, onAction }: MessageToolbarProps) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className="flex items-center gap-0.5 mt-2 -ml-1 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
      <Btn label={copied ? "Copied" : "Copy"} onClick={copy} icon={copied ? Check : Copy} active={copied} />
      {/* Rating sits first: it is the one action we want to be effortless, and
          it is the only one whose value compounds — every vote makes the next
          dataset less of an echo of the model's own past answers. */}
      <Btn
        label={message.rating === "up" ? "Good answer (click to undo)" : "Good answer"}
        onClick={() => onAction("rateUp", message)}
        icon={ThumbsUp}
        active={message.rating === "up"}
      />
      <Btn
        label={message.correction ? "Corrected — click to edit" : "Wrong — tell it why"}
        onClick={() => onAction("rateDown", message)}
        icon={ThumbsDown}
        active={message.rating === "down"}
      />
      <span className="w-px h-4 bg-oyster-border mx-1" />
      <Btn label="Regenerate" onClick={() => onAction("regenerate", message)} icon={RefreshCw} />
      <Btn label="Summarize" onClick={() => onAction("summarize", message)} icon={FileText} />
      <Btn label="Explain" onClick={() => onAction("explain", message)} icon={Sparkles} />
      <span className="w-px h-4 bg-oyster-border mx-1" />
      {/* Evidence-capture actions — both live. Tinted red so they read as the
          "capture this" group, distinct from the utility actions around them. */}
      <Btn label="Create Finding" onClick={() => onAction("createFinding", message)} icon={Bug} capture />
      <Btn label="Add to Report" onClick={() => onAction("addToReport", message)} icon={ClipboardCheck} capture />
      <span className="w-px h-4 bg-oyster-border mx-1" />
      <Btn label="Pin" onClick={() => onAction("pin", message)} icon={Pin} active={message.pinned} />
      <Btn label="Bookmark" onClick={() => onAction("bookmark", message)} icon={Bookmark} active={message.bookmarked} />
    </div>
  );
}

function Btn({
  label,
  onClick,
  icon: Icon,
  active,
  capture,
}: {
  label: string;
  onClick: () => void;
  icon: React.ElementType;
  active?: boolean;
  /** Evidence-capture action (Create Finding / Add to Report) — rendered red. */
  capture?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      className={`cursor-pointer p-1.5 rounded-md transition-colors ${
        active
          ? "text-oyster-accent"
          : capture
          ? "text-red-400 hover:text-red-300 hover:bg-red-500/10"
          : "text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface"
      }`}
    >
      <Icon
        size={13}
        className={
          active && (label === "Pin" || label === "Bookmark" || label.startsWith("Good") ||
                     label.startsWith("Wrong") || label.startsWith("Corrected"))
            ? "fill-current"
            : ""
        }
      />
    </button>
  );
}
