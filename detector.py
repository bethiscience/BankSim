"""Detection engine (Phase 3): normalization + deterministic rules + pluggable classifier.

Pure text-in / verdict-out. It imports nothing from the banking side, so the Hell Track
worker can reuse it without gaining any banking capability.

Two depths:
  * lightweight (Superfast Lane): rules on the base / spaced-letter / leet / rot13 variants only.
  * deep (Standard Lane & Hell Track): adds base64-decoded variants and the classifier.
Obfuscation markers found during normalization raise the risk, which makes a Superfast
request escalate to the deep path (see firewall.py).
"""
import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Protocol

import config
from schemas import ThreatCategory as TC

# ----------------------------------------------------------------------------
# Normalization
# ----------------------------------------------------------------------------
_ZERO_WIDTH = {ord(c): None for c in
               "\u200b\u200c\u2060\ufeff\u180e\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"}
# Common Cyrillic/Greek look-alikes -> Latin
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ο": "o", "α": "a", "ε": "e", "ν": "v", "ι": "i",
    "κ": "k", "τ": "t", "ρ": "p", "υ": "u", "Α": "a", "Ε": "e", "Ο": "o", "Ρ": "p", "Τ": "t",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SPACED = re.compile(r"\b(?:\w[ .\-_*|]){3,}\w\b")
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])")

MARKER_WEIGHTS = {
    "ZERO_WIDTH": 0.35, "CONTROL_CHARS": 0.35, "HOMOGLYPH": 0.30, "BASE64_PAYLOAD": 0.35,
    "SPACED_LETTERS": 0.20, "URL_ENCODING": 0.15, "HTML_ENTITY": 0.15,
}


@dataclass
class Normalized:
    variants: list            # [(label, text)]
    markers: set = field(default_factory=set)


def normalize(text: str, deep: bool) -> Normalized:
    markers: set[str] = set()
    t = text
    if any(ord(c) in _ZERO_WIDTH for c in t):
        markers.add("ZERO_WIDTH")
        t = t.translate(_ZERO_WIDTH)
    if any(unicodedata.category(c) == "Cc" and c not in "\n\r\t" for c in t):
        markers.add("CONTROL_CHARS")
        t = "".join(" " if (unicodedata.category(c) == "Cc" and c not in "\n\r\t") else c for c in t)
    folded = unicodedata.normalize("NFKC", t)
    h = folded.translate(_HOMOGLYPHS)
    if h != folded:
        markers.add("HOMOGLYPH")
    t = h
    u = html.unescape(t)
    if u != t:
        markers.add("HTML_ENTITY")
        t = u
    if "%" in t:
        u = urllib.parse.unquote(t)
        if u != t:
            markers.add("URL_ENCODING")
            t = u
    original_case = t                      # base64 is case-sensitive: decode before casefolding
    t = re.sub(r"[ \t\r\f\v]+", " ", t.casefold())

    variants = [("base", t)]
    collapsed = _SPACED.sub(lambda m: re.sub(r"[ .\-_*|]", "", m.group()), t)
    if collapsed != t:
        markers.add("SPACED_LETTERS")
        variants.append(("spaced", collapsed))
    leet = collapsed.translate(_LEET)
    if leet != collapsed:
        variants.append(("leet", leet))

    # base64 payloads: always flag (cheap), only decode-and-scan on the deep path
    for tok in _B64_TOKEN.findall(original_case):
        dec = _try_b64(tok)
        if dec:
            markers.add("BASE64_PAYLOAD")
            if deep:
                variants.append(("base64", dec.casefold()))
    # rot13 of ordinary text is gibberish, so scanning it is cheap and safe on both lanes
    variants.append(("rot13", codecs.decode(t, "rot13")))
    return Normalized(variants, markers)


def _try_b64(tok: str) -> Optional[str]:
    try:
        raw = base64.b64decode(tok.replace("-", "+").replace("_", "/") + "=" * (-len(tok) % 4), validate=True)
        s = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in s)
    letters = sum(ch.isalpha() for ch in s)
    return s if (len(s) and printable / len(s) >= 0.9 and letters >= 8) else None


# ----------------------------------------------------------------------------
# Rules
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    name: str
    category: TC
    weight: float
    scope: str               # "all" (message + memo) or "memo" (transaction memo only)
    pattern: re.Pattern


def _r(name, cat, weight, scope, pat) -> Rule:
    return Rule(name, cat, weight, scope, re.compile(pat, re.I | re.M))


_Q = r"(?:(?:all|any|every|everything|the|your|you|my|previous|prior|above|earlier|preceding|former|original|initial|safety|security|system|these|those|of|and|were|given|been|told)\W+)"
_W = r"(?:\w+\W+)"
PI, JB, MM = TC.PROMPT_INJECTION, TC.JAILBREAK, TC.MALICIOUS_MEMO

RULES: list[Rule] = [
    # --- prompt injection (message + memo) ---
    _r("ignore_instructions", PI, 0.95, "all",
       rf"\b(?:ignore|disregard|forget|override|bypass|discard|neglect)\W+{_Q}{{0,5}}(?:instructions?|prompts?|rules?|directives?|guidelines?|polic(?:y|ies)|restrictions?|constraints?|safeguards?|programming|training)\b"),
    _r("disregard_above", PI, 0.85, "all",
       r"\b(?:disregard|ignore)\W+(?:the\W+)?(?:above|previous|prior|earlier|preceding)\b(?!\W+(?:message|email|memo|typo|note|text|payment|transfer|request)\b)"),
    _r("forget_everything", PI, 0.85, "all",
       r"\bforget\W+(?:everything|all)\W+(?:that\W+)?(?:you|above|previous|prior|before)\b"),
    _r("reveal_system_prompt", PI, 0.90, "all",
       rf"\b(?:reveal|show|print|repeat|leak|output|display|tell me)\W+{_W}{{0,3}}?(?:system|hidden|initial|developer|secret)\W+(?:prompt|instructions?|message|rules)\b"),
    _r("fake_role_marker", PI, 0.85, "all",
       r"(?:\[\s*(?:system|assistant|admin|developer)\s*\]|<\|?\s*(?:system|im_start|im_end|assistant)\s*\|?>|</?\s*(?:system|instructions?)\s*>|^\s*(?:system|assistant|developer)\s*:|^\s*#{2,}\s*(?:system|instruction))"),
    _r("new_instructions", PI, 0.80, "all",
       r"\b(?:new|updated|revised|additional|real)\s+(?:instructions?|directives?|rules?)\s*[:\-]"),
    _r("you_are_now", PI, 0.70, "all", r"\byou\s+are\s+(?:now|no\s+longer)\b"),
    _r("from_now_on", PI, 0.60, "all", r"\bfrom\s+now\s+on\b.{0,50}\b(?:you|assistant|ai)\b"),
    _r("safety_disable", PI, 0.85, "all",
       rf"\b(?:disable|turn\s+off|deactivate|skip|bypass|circumvent|suppress)\W+(?:{_W}){{0,3}}?(?:fraud|security|verification|authentication|2fa|otp|checks?|limits?|firewall|safeguards?|monitoring|alerts?|audit)\b"),
    # --- jailbreak / roleplay (message + memo) ---
    _r("dan_jailbreak", JB, 0.90, "all",
       r"\bdo\s+anything\s+now\b|\bdan\s+mode\b|\b(?:you\s+are|act\s+as|be|become)\s+dan\b|\bjailbr(?:eak|oken)\b"),
    _r("special_mode", JB, 0.80, "all",
       r"\b(?:developer|god|sudo|admin|root|unrestricted|unfiltered)\s+mode\b"),
    _r("roleplay_unrestricted", JB, 0.85, "all",
       r"\b(?:act|behave|respond|roleplay|role-play|play)\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?(?:an?\s+|the\s+)?(?:\w+\s+){0,3}?(?:unrestricted|unfiltered|uncensored|jailbroken|evil|admin|root|system|developer)\b"),
    _r("pretend", JB, 0.65, "all", r"\bpretend\s+(?:that\s+)?(?:you|to\s+be|you're|you\s+are)\b"),
    _r("hypothetical_no_rules", JB, 0.70, "all",
       r"\bhypothetical(?:ly)?\b.{0,60}\b(?:no|without)\s+(?:rules|restrictions|limits|safeguards|filters)\b"),
    _r("no_restrictions_ai", JB, 0.75, "all",
       r"\b(?:without|no|free\s+(?:of|from))\s+(?:any\s+)?(?:restrictions|filters|guidelines|censorship|safety\s+rules)\b.{0,60}\b(?:you|assistant|ai)\b"),
    # --- tool-directed content that has no business in a transaction memo ---
    _r("tool_call_syntax", MM, 0.90, "memo",
       r"\btool_call\b|\bfunction_call\b|[\"']?action[\"']?\s*[:=]\s*[\"']?(?:transfer|send|approve|withdraw)|\bexecute_?transfer\b|\bcall\s+(?:the\s+)?(?:transfer|payment|banking)\s+(?:tool|function|api)\b"),
    _r("drain_funds", MM, 0.85, "memo",
       rf"\b(?:transfer|send|wire|move|withdraw|pay)\W+{_W}{{0,4}}?(?:all|everything|entire|full|max(?:imum)?|remaining)\W+{_W}{{0,2}}?(?:funds|money|balance|savings|amount)\b"),
    _r("approve_directive", MM, 0.70, "memo",
       rf"\b(?:approve|authori[sz]e|confirm|release|execute|process)\W+{_W}{{0,2}}?(?:transfer|transaction|payment|withdrawal)s?\b"),
    _r("trust_manipulation", MM, 0.85, "memo",
       rf"\b(?:add|mark|set|register|treat|whitelist|allowlist)\W+{_W}{{0,4}}?(?:trusted|verified|whitelist|allowlist|safe|approved)\b"),
    _r("limit_change", MM, 0.55, "memo",
       rf"\b(?:raise|increase|remove|change|lift|override)\W+{_W}{{0,3}}?(?:limit|cap|threshold)s?\b"),
    _r("addresses_assistant", MM, 0.80, "memo",
       r"\b(?:dear|hey|hello|attention|note\s+to|message\s+for|instruction\s+for|notice\s+to|to\s+the)\s+(?:ai|assistant|bot|agent|model|system|llm|chatbot)\b"),
    _r("exfiltration", MM, 0.80, "memo",
       rf"\b(?:send|email|forward|post|leak|share|reveal)\W+{_W}{{0,4}}?(?:password|credentials?|api\s+key|token|pin|otp|account\s+(?:number|details)|balance|history|ssn)\b"),
    _r("markdown_exfil", MM, 0.80, "memo", r"!\[[^\]]*\]\(\s*https?://"),
    _r("coercion", MM, 0.80, "memo",
       r"\bwithout\s+(?:asking|confirmation|verification|checking)\b|\b(?:do\s*not|don'?t)\s+(?:tell|notify|alert|inform)\b"),
    _r("code_injection", MM, 0.80, "memo",
       r";\s*(?:drop|delete|update|insert)\s+\w+|\bunion\s+select\b|<script\b|\$\([^)]*\)"),
    _r("memo_url", MM, 0.35, "memo", r"https?://\S+"),
    _r("urgency", MM, 0.20, "memo", r"\b(?:urgent|immediately|asap|right\s+now)\b"),
]


# ----------------------------------------------------------------------------
# Classifier backends
# ----------------------------------------------------------------------------
class ClassifierBackend(Protocol):
    name: str
    def score(self, text: str) -> float: ...


_AI = re.compile(r"\b(?:assistant|ai|bot|chatbot|agent|model|llm|system|gpt|claude)\b")
_IMP = re.compile(r"\b(?:ignore|forget|disregard|reveal|send|transfer|approve|disable|override|execute|pretend|act|obey|comply|bypass|delete|grant|unlock|authori[sz]e|release)\b")
_MODAL = re.compile(r"\b(?:you\s+must|you\s+should|you\s+will|you\s+have\s+to|make\s+sure\s+you|do\s+not\s+refuse|never\s+refuse|always\s+(?:comply|obey))\b")


class HeuristicClassifier:
    """Cheap, dependency-free stand-in for the specialized classifier.

    It catches *paraphrased* instructions aimed at the AI that the literal rules miss.
    Its output is capped below the block threshold on purpose: alone it can escalate
    a request, but a block needs a rule hit or the real model.
    """
    name = "heuristic-v1"

    def score(self, text: str) -> float:
        s = 0.0
        imps = _IMP.findall(text)
        if _AI.search(text) and imps:
            s += 0.35
        if _MODAL.search(text):
            s += 0.30
        if len(imps) >= 3:
            s += 0.15
        if text.count("\n") >= 3:
            s += 0.10
        if len(text) > 300:
            s += 0.10
        return min(s, 0.70)


class HFClassifier:
    """Optional Hugging Face text-classification model (BANKSIM_USE_HF=1).

    NOT benchmarked here: before relying on it, check accuracy, latency and licence of
    the chosen model on your own labelled data.
    """
    def __init__(self, model_name: str):
        from transformers import pipeline  # lazy: heavy import
        self.name = model_name
        self._pipe = pipeline("text-classification", model=model_name, truncation=True, max_length=512)

    def score(self, text: str) -> float:
        out = self._pipe(text[:2000])[0]
        label, p = str(out["label"]).upper(), float(out["score"])
        injected = ("INJECTION" in label) or label in {"LABEL_1", "UNSAFE", "MALICIOUS", "JAILBREAK"}
        return p if injected else 1.0 - p


def get_classifier() -> ClassifierBackend:
    if config.USE_HF_CLASSIFIER:
        try:
            return HFClassifier(config.HF_MODEL)
        except Exception:      # fall back, never fail open or crash the firewall
            pass
    return HeuristicClassifier()


# ----------------------------------------------------------------------------
# Detector
# ----------------------------------------------------------------------------
@dataclass
class Detection:
    risk: float
    category: TC
    rules: list = field(default_factory=list)
    markers: list = field(default_factory=list)
    fields: list = field(default_factory=list)
    classifier_score: Optional[float] = None
    deep: bool = False


def noisy_or(parts) -> float:
    p = 1.0
    for x in parts:
        p *= 1.0 - max(0.0, min(1.0, x))
    return min(0.99, round(1.0 - p, 4))


class Detector:
    def __init__(self, classifier: Optional[ClassifierBackend] = None):
        self.classifier = classifier or get_classifier()

    def inspect(self, message: str = "", memo: str = "", deep: bool = True) -> Detection:
        hits: dict[str, tuple[Rule, set]] = {}
        markers: set[str] = set()
        for field_name, text in (("message", message), ("memo", memo)):
            if not text:
                continue
            norm = normalize(text, deep)
            markers |= norm.markers
            for label, variant in norm.variants:
                for rule in RULES:
                    if rule.scope == "memo" and field_name != "memo":
                        continue
                    if rule.pattern.search(variant):
                        entry = hits.setdefault(rule.name, (rule, set()))
                        entry[1].add(field_name)

        parts = [r.weight for r, _ in hits.values()]
        if markers:
            parts.append(max(MARKER_WEIGHTS[m] for m in markers))

        cls_score = None
        if deep and (message or memo):
            cls_score = round(self.classifier.score(f"{message}\n{memo}".strip().casefold()), 4)
            parts.append(cls_score)

        category = TC.NONE
        if hits:
            category = max(hits.values(), key=lambda h: h[0].weight)[0].category
        elif cls_score is not None and cls_score >= config.THRESH_FAST_ESCALATE:
            category = TC.PROMPT_INJECTION

        fields = sorted({f for _, fs in hits.values() for f in fs})
        return Detection(noisy_or(parts), category, sorted(hits), sorted(markers), fields, cls_score, deep)
