export function normalizeUrl(input: string): string {
  let url = input.trim();

  // Add protocol if missing
  if (!/^https?:\/\//i.test(url)) {
    url = 'http://' + url;
  }

  return url;
}

export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}
