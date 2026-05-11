"use client";

import { useState } from "react";
import CommandForm from "./CommandForm";
import ExampleCommands from "./ExampleCommands";

interface Workspace { id: string; name: string }

export default function HomeContent({
  loggedIn = false,
  workspaces = [],
}: {
  loggedIn?: boolean;
  workspaces?: Workspace[];
}) {
  const [prefill, setPrefill] = useState("");

  return (
    <>
      {/* key forces CommandForm to remount (re-init state) when example selected */}
      <CommandForm key={prefill} defaultCommand={prefill} loggedIn={loggedIn} workspaces={workspaces} />
      <div className="w-full border-t border-[var(--border)] pt-6">
        <ExampleCommands onSelect={setPrefill} />
      </div>
    </>
  );
}
