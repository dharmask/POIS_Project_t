import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { PA10Page } from "../PA10Page";

describe("PA10Page", () => {
  it("renders the hmac tab by default", () => {
    render(<PA10Page tab="hmac" onTabChange={vi.fn()} onBack={vi.fn()} />);

    expect(screen.getByText("PA #10 - HMAC and HMAC-Based CCA Encryption")).toBeInTheDocument();
    expect(screen.getAllByText("HMAC from the PA8 DLP Hash").length).toBeGreaterThan(0);
    expect(screen.getByText("Compute HMAC")).toBeInTheDocument();
  });

  it("renders the security demo tab", () => {
    render(<PA10Page tab="security" onTabChange={vi.fn()} onBack={vi.fn()} />);

    expect(screen.getAllByText("CCA Security Demo").length).toBeGreaterThan(0);
    expect(screen.getByText("Run Tamper Demo")).toBeInTheDocument();
    expect(screen.getByText("Run CCA Game")).toBeInTheDocument();
  });
});
