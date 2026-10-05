export type PluralForm = "one" | "few" | "many";

/* CLDR's rule for whole numbers: Russian has three forms, English two. */
export function pluralForm(n: number, locale: string): PluralForm {
  if (locale === "ru") {
    const d = n % 10;
    const h = n % 100;
    if (d === 1 && h !== 11) return "one";
    if (d >= 2 && d <= 4 && (h < 12 || h > 14)) return "few";
    return "many";
  }
  return n === 1 ? "one" : "many";
}

/* `one`/`few`/`many` carry `{n}` where the number goes. */
export function counted(n: number, locale: string, one: string, few: string, many: string): string {
  const form = pluralForm(n, locale);
  return (form === "one" ? one : form === "few" ? few : many).replace("{n}", String(n));
}
