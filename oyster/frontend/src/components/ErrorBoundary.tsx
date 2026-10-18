"use client";

import { Component, type ErrorInfo, type ReactNode } from "react";
import { RefreshCw } from "lucide-react";

/**
 * A render crash used to unmount the whole tree to a blank page. Wrapping the
 * chat pane keeps the sidebar alive, offers a reset, and never shows the
 * exception's own words (they may name files or hosts).
 */
interface Props {
  children: ReactNode;
  /** Change this to remount the subtree (e.g. the active conversation id). */
  resetKey?: string;
}

interface State {
  failed: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Console only: the message may carry internals. Nothing is sent anywhere.
    console.error("Oyster: a panel crashed", error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (prev.resetKey !== this.props.resetKey && this.state.failed) {
      this.setState({ failed: false });
    }
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="flex-1 min-w-0 h-app flex items-center justify-center bg-oyster-bg px-6">
        <div className="text-center max-w-sm">
          <p className="text-oyster-text text-[15px] mb-1">This part of Oyster hit a problem.</p>
          <p className="text-oyster-muted text-sm mb-5">
            Your conversations are safe. Try again, or reload the page.
          </p>
          <div className="flex items-center justify-center gap-2">
            <button
              onClick={() => this.setState({ failed: false })}
              className="cursor-pointer inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-oyster-accent text-white text-sm hover:bg-oyster-accent-hover transition-colors"
            >
              <RefreshCw size={14} />
              Try again
            </button>
            <button
              onClick={() => window.location.reload()}
              className="cursor-pointer px-4 py-2 rounded-lg border border-oyster-border text-oyster-text text-sm hover:bg-oyster-surface transition-colors"
            >
              Reload
            </button>
          </div>
        </div>
      </div>
    );
  }
}
