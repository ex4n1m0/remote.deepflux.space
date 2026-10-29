/** Discovery-list UI state (ADR-010): the decrypted circle directory as
 * app-layer state — never engine state (the engine knows nothing about
 * circles). Pure reducer, wired to transport by `useDirectory`. */

import type { DirectoryMachine } from "../types";

export interface DirectoryUiState {
  loaded: boolean;
  machines: DirectoryMachine[];
}

export function initialDirectoryState(): DirectoryUiState {
  return { loaded: false, machines: [] };
}

export type DirectoryAction =
  | { type: "machines"; machines: DirectoryMachine[] }
  | { type: "loaded" };

export function directoryReducer(
  state: DirectoryUiState,
  action: DirectoryAction,
): DirectoryUiState {
  switch (action.type) {
    case "machines":
      return { ...state, machines: action.machines };
    case "loaded":
      return { ...state, loaded: true };
  }
}
