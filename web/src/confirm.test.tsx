import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ConfirmHost, confirmDialog } from "@/components/Confirm";
import { I18nProvider } from "@/i18n/i18n";

describe("typed confirmation", () => {
  it("keeps the action disabled until the exact name is typed", async () => {
    render(<I18nProvider initial="en"><ConfirmHost /></I18nProvider>);
    let result: boolean | undefined;
    await act(async () => { void confirmDialog("Delete site?", { typed: "shop" }).then((v) => (result = v)); });
    const btn = screen.getByRole("button", { name: "Confirm" });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Type shop to confirm"), { target: { value: "sho" } });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Type shop to confirm"), { target: { value: "shop" } });
    expect(btn).toBeEnabled();
    await act(async () => { fireEvent.click(btn); });
    expect(result).toBe(true);
  });
});
