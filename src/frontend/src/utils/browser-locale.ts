export function browserLocale(
  nav: { languages?: readonly string[]; language?: string } | undefined,
) {
  const list = nav?.languages?.length ? nav.languages : nav?.language ? [nav.language] : [];
  const first = list[0]?.toLowerCase().split(/[-_]/)[0];
  return first === "ru" ? "ru" : "en";
}
