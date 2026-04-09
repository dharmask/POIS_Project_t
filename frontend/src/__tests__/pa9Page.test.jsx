import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { PA9Page } from "../PA9Page";

describe("PA9Page", () => {
  it("renders the live demo tab by default", () => {
    render(<PA9Page tab="live" onTabChange={vi.fn()} onBack={vi.fn()} />);

    expect(screen.getByText("PA #9 - Birthday Attack (Collision Finding)")).toBeInTheDocument();
    expect(screen.getByText("Live Demo")).toBeInTheDocument();
    expect(screen.getByText("Interactive Birthday Attack Demo")).toBeInTheDocument();
  });

  it("renders the DLP attack panel when that tab is selected", () => {
    render(<PA9Page tab="dlpattack" onTabChange={vi.fn()} onBack={vi.fn()} />);

    expect(screen.getByText("Attack Truncated PA8 DLP Hash")).toBeInTheDocument();
    expect(screen.getByText("Attack 16-bit DLP Hash")).toBeInTheDocument();
  });
});
