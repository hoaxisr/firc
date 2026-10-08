import { expect, type Page } from "@playwright/test";

export async function answerConfirm(page: Page, ok: boolean): Promise<string> {
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toBeVisible();
  const title = (await dialog.locator(".confirm-title").textContent()) ?? "";
  await dialog.locator(ok ? ".confirm-action" : ".confirm-cancel").click();
  await expect(dialog).toHaveCount(0);
  return title;
}
