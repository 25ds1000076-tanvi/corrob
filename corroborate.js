/**
 * OSINT Corroboration Engine — decision logic
 *
 * Pure function: given the parsed request body, returns the response object.
 * Never reads the wall clock — all "now" comes from `asOf` in the request.
 */

const VALID_TYPES = new Set(["dns", "ct_log", "registry", "archive", "scan"]);

function isPlainObject(x) {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function invalidResponse() {
  return { verdict: "invalid", confidence: "low", corroboratingSources: [] };
}

function corroborate(body) {
  // --- Rule 1: basic shape validation ---
  if (!isPlainObject(body)) return invalidResponse();

  const { claim, asOf, stalenessDays, sources } = body;

  if (!isPlainObject(claim) || typeof claim.value !== "string") {
    return invalidResponse();
  }

  const asOfMs = Date.parse(asOf);
  if (typeof asOf !== "string" || Number.isNaN(asOfMs)) {
    return invalidResponse();
  }

  if (typeof stalenessDays !== "number" || Number.isNaN(stalenessDays)) {
    return invalidResponse();
  }

  if (!Array.isArray(sources)) return invalidResponse();

  // --- Drop malformed sources entirely (does NOT invalidate the request) ---
  const validSources = sources.filter((s) => {
    return (
      isPlainObject(s) &&
      typeof s.id === "string" &&
      typeof s.origin === "string" &&
      typeof s.value === "string" &&
      typeof s.observedAt === "string" &&
      VALID_TYPES.has(s.type)
    );
  });

  // --- Determine freshness ---
  const MS_PER_DAY = 24 * 60 * 60 * 1000;
  const fresh = validSources.filter((s) => {
    const observedMs = Date.parse(s.observedAt);
    if (Number.isNaN(observedMs)) return false; // unparseable date => not usable
    const ageDays = (asOfMs - observedMs) / MS_PER_DAY;
    return ageDays <= stalenessDays;
  });

  // --- Rule 2: contradiction check (authoritative, fresh, disagreeing) ---
  const contradicting = fresh
    .filter((s) => s.authoritative === true && s.value !== claim.value)
    .map((s) => s.id)
    .sort();

  if (contradicting.length > 0) {
    return {
      verdict: "contradicted",
      confidence: "low",
      corroboratingSources: contradicting,
    };
  }

  // --- Rule 3: support check ---
  // Fresh sources that agree with the claim
  const agreeing = fresh.filter((s) => s.value === claim.value);

  // One representative per origin: smallest id wins
  const bestByOrigin = new Map(); // origin -> source
  for (const s of agreeing) {
    const current = bestByOrigin.get(s.origin);
    if (!current || s.id < current.id) {
      bestByOrigin.set(s.origin, s);
    }
  }

  const representatives = [...bestByOrigin.values()];

  if (representatives.length >= 2) {
    const distinctTypes = new Set(representatives.map((s) => s.type));
    const confidence = distinctTypes.size >= 2 ? "high" : "medium";
    const corroboratingSources = representatives.map((s) => s.id).sort();

    return {
      verdict: "supported",
      confidence,
      corroboratingSources,
    };
  }

  // --- Rule 4: fallback ---
  return { verdict: "unverified", confidence: "low", corroboratingSources: [] };
}

module.exports = { corroborate };
