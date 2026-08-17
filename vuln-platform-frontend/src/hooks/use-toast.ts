"use client";

// Minimal reimplementation of shadcn's use-toast: a module-level
// store (not React context) so any component/hook — including
// non-component code like a React Query onError callback — can fire
// a toast without needing to be inside a specific provider tree.
import * as React from "react";
import type { ToastProps } from "@/components/ui/toast";

const TOAST_LIMIT = 3;
const TOAST_REMOVE_DELAY = 5000;

type ToasterToast = ToastProps & {
  id: string;
  title?: React.ReactNode;
  description?: React.ReactNode;
};

let count = 0;
function genId() {
  count = (count + 1) % Number.MAX_SAFE_INTEGER;
  return count.toString();
}

type State = { toasts: ToasterToast[] };
type Action =
  | { type: "ADD_TOAST"; toast: ToasterToast }
  | { type: "DISMISS_TOAST"; toastId?: string }
  | { type: "REMOVE_TOAST"; toastId?: string };

const listeners: Array<(state: State) => void> = [];
let memoryState: State = { toasts: [] };

function dispatch(action: Action) {
  memoryState = reducer(memoryState, action);
  listeners.forEach((listener) => listener(memoryState));
}

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "ADD_TOAST":
      return { toasts: [action.toast, ...state.toasts].slice(0, TOAST_LIMIT) };
    case "DISMISS_TOAST":
    case "REMOVE_TOAST":
      if (action.toastId === undefined) return { toasts: [] };
      return { toasts: state.toasts.filter((t) => t.id !== action.toastId) };
    default:
      return state;
  }
}

function toast(props: Omit<ToasterToast, "id">) {
  const id = genId();
  dispatch({ type: "ADD_TOAST", toast: { ...props, id } });
  setTimeout(() => dispatch({ type: "REMOVE_TOAST", toastId: id }), TOAST_REMOVE_DELAY);
  return id;
}

function useToast() {
  const [state, setState] = React.useState<State>(memoryState);

  React.useEffect(() => {
    listeners.push(setState);
    return () => {
      const idx = listeners.indexOf(setState);
      if (idx > -1) listeners.splice(idx, 1);
    };
  }, []);

  return { ...state, toast, dismiss: (toastId?: string) => dispatch({ type: "DISMISS_TOAST", toastId }) };
}

export { useToast, toast };
