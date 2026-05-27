import { create } from "zustand";
import type { CallChainData } from "../api/types";

interface PinnedChain {
  data: CallChainData;
  rootFunction: string;
  direction: "backward" | "forward";
}

interface ChainState {
  pinned: PinnedChain | null;
  position: { x: number; y: number };
  size: { width: number; height: number };

  pin: (data: CallChainData, rootFunction: string, direction: "backward" | "forward") => void;
  unpin: () => void;
  setPosition: (x: number, y: number) => void;
  setSize: (width: number, height: number) => void;
}

const DEFAULT_WIDTH = 420;
const DEFAULT_HEIGHT = 360;

function defaultPosition() {
  if (typeof window === "undefined") return { x: 100, y: 100 };
  return {
    x: Math.max(20, window.innerWidth - DEFAULT_WIDTH - 24),
    y: Math.max(20, window.innerHeight - DEFAULT_HEIGHT - 24),
  };
}

export const useChainStore = create<ChainState>((set) => ({
  pinned: null,
  position: defaultPosition(),
  size: { width: DEFAULT_WIDTH, height: DEFAULT_HEIGHT },

  pin: (data, rootFunction, direction) =>
    set({ pinned: { data, rootFunction, direction } }),
  unpin: () => set({ pinned: null }),
  setPosition: (x, y) => set({ position: { x, y } }),
  setSize: (width, height) => set({ size: { width, height } }),
}));
