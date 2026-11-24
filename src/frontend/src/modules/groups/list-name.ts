export function listName(url: string): string {
  const path = url.replace(/[?#].*$/, "").replace(/\/+$/, "");
  const tail = path.slice(path.lastIndexOf("/") + 1);
  return tail && !path.endsWith(`//${tail}`) ? tail : path.replace(/^[a-z]+:\/\//i, "");
}
