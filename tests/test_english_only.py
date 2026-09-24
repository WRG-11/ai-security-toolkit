"""Every tracked text file is free of the one non-English language that used to fill it.

This replaces an older test that checked only comments and docstrings and let
non-English data strings through as a "multilingual corpus". That exemption hid
the larger problem: 163 of the 194 attack probes were in that language, written
without diacritics, so the scanner was measuring how models answer attacks in
one particular language. The lab corpus, the defenses' training samples and
the shipped model all carried it. A checker that looked only at the files a
change touched never saw any of it, because those files had not changed.

How it decides: a letter specific to that language, or a token from a curated
list of its words written in ASCII. The list is stored as truncated SHA-256
hashes so this file does not reproduce the words it looks for. Stems match as
a token prefix, because the language is suffixing; short words match whole.
Words with an English (or German, Spanish, French) homograph are left out on
purpose.

What this does NOT answer: whether a string is good English, or whether text
in any other language is present. It is a floor, not a translation review --
the list only knows the words someone added to it, so a miss is possible.
"""
from __future__ import annotations

import codecs
import hashlib
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MARKER_LETTERS = frozenset("\u00e7\u011f\u0131\u00f6\u015f\u00fc\u00c7\u011e\u0130\u00d6\u015e\u00dc")

WHOLE_WORDS = frozenset({
    "00050806abd4", "0ae941bed711", "11ff5fd16860", "158e8c460a24", "20bc4f86ec41", "214686109380",
    "23f31d553dea", "2d21ad189dc8", "3201218833b4", "358283e045a2", "368b11590f7b", "39bc770f1e84",
    "3bcffce9a0d2", "4bd2c412ba70", "4c6bcdd55f31", "552d2e026311", "59642a7ba5d4", "64b8141c22bc",
    "64dbd97d5543", "697fedd52922", "784d2fbb38b9", "7b50943dab3f", "7ef37f00a53f", "7f2bb01023bf",
    "81ae99b34fef", "8c10715386ff", "8d1b1614859d", "8f2234d6ac90", "8f3eebb6dd77", "946b8a7467b4",
    "9508394fe63a", "96dd46fa3264", "b32c73e523a9", "b43041e8ca1e", "b4f539ac447c", "b5acc5032794",
    "b689a6533bfc", "b75d4329d22a", "b797e98fff6c", "b83cecac4fb8", "b8becfe8943a", "c08da3b9413c",
    "cad4908f87c2", "cbb7dcae9c7b", "ced90303a24f", "d005a6aaabab", "d31f59cef94f", "d7bbae78b2d5",
    "d7c5e8a97c0f", "e7be2548d541", "eaa2f4aaff3b", "edfaec819a26", "ee73e0bb7a5c", "f1a036ece85e",
    "f8fa8a82e9e8",
})

STEMS = frozenset({
    (4, "43db008dafb4"), (4, "5359507df682"), (5, "043539107511"), (5, "11fa7f5fd1a8"), (5, "13a7a134e991"),
    (5, "256cc7e9e3e5"), (5, "29e118a3b379"), (5, "2cc604b5fc50"), (5, "2d2bcf02cc5e"), (5, "31859895f8e3"),
    (5, "3a4a83a3029d"), (5, "3bba395bda56"), (5, "3fab83486ada"), (5, "429aa7db0723"), (5, "46e5aa5ef4a0"),
    (5, "488a684d2565"), (5, "4bee78a14d62"), (5, "4ff9958b6fd2"), (5, "5037bac59db1"), (5, "550760cc71f8"),
    (5, "580ef5448272"), (5, "64dbf5d28b8c"), (5, "6955dafb3de4"), (5, "74059022c51f"), (5, "76c03e3e53b3"),
    (5, "7ab40bfc8f56"), (5, "826ed8cff3d2"), (5, "869f4cbc5cdc"), (5, "889d3edb31f0"), (5, "8f37491f3a35"),
    (5, "8f7d751e5c0e"), (5, "90ccb7481686"), (5, "9c2507354e06"), (5, "9efadbe17095"), (5, "9f2fb4fd0fab"),
    (5, "a1b3f812eb66"), (5, "a2de6f1a74cb"), (5, "a3b7775c93a7"), (5, "a5fa7ae8b242"), (5, "a70fe208b1af"),
    (5, "acc3975bb18f"), (5, "b0a4c59121b8"), (5, "b68070a072de"), (5, "bc5bed98c0fb"), (5, "c80c43fb97a8"),
    (5, "c93ea816e92c"), (5, "c9dd855a0966"), (5, "d219a951dadf"), (5, "d7ec5d77d5e9"), (5, "d7fe1c83c735"),
    (5, "db2945ecc959"), (5, "dea75dcf4107"), (5, "e16081fbe303"), (5, "e5af5efcbefb"), (5, "e8f32ff836b5"),
    (5, "f0efbfe39a0b"), (5, "fde3b969fa0e"), (5, "fe07c6dbae2a"), (5, "fede8754e188"), (5, "ffcf09208e04"),
    (6, "09508c3f37a8"), (6, "0a09eb4809a0"), (6, "0aed1ed0e2da"), (6, "0d4669271f8c"), (6, "0f3782ee8f72"),
    (6, "0f7d070586d3"), (6, "19f483e5a071"), (6, "1c94fa9292b7"), (6, "25f9ab234f2c"), (6, "290b363cfbab"),
    (6, "389695db7cb0"), (6, "39027d415061"), (6, "48b53e9b883c"), (6, "4ad044e910f8"), (6, "53de77b56073"),
    (6, "5a115287f883"), (6, "5e5ac7f820c8"), (6, "61ba59abf7d3"), (6, "6873e72e8f0a"), (6, "6acb4268da50"),
    (6, "6b13025b2606"), (6, "72bc15694a67"), (6, "752fd269a58b"), (6, "793e10dba01a"), (6, "8908908ab375"),
    (6, "a3058942a6af"), (6, "a80b568a237f"), (6, "bdcff2aa7f2d"), (6, "c1dec5bc249a"), (6, "c57a8acde4e2"),
    (6, "caf428489a7f"), (6, "ce15f335f4d8"), (6, "ce2d98ef6f51"), (6, "ceaa12117ef6"), (6, "cf3ae485df23"),
    (6, "d2e7d143b3bd"), (6, "d4178443a567"), (6, "d4a2e305f47f"), (6, "d7c0b79ffd5a"), (6, "dbbdddd5f5e2"),
    (6, "e4484aca9f8f"), (6, "e6b6203d5012"), (6, "eb4ae47711aa"), (6, "fb0446ed98d7"), (6, "fc6dfde8f1ef"),
    (6, "fd1619576f3a"), (7, "0b46aba64aae"), (7, "11fa80229952"), (7, "1631c0319fd7"), (7, "18b317b5b7d4"),
    (7, "236ac14696bb"), (7, "23a87fb0f8d7"), (7, "2765ca5cd10a"), (7, "2d574971cb0e"), (7, "363b40ca3fef"),
    (7, "371fa0259963"), (7, "402c98e97a11"), (7, "4d2da9f07bca"), (7, "4d7cf61ec380"), (7, "54cb9b68e967"),
    (7, "55ea4bcef65b"), (7, "55f10450eadf"), (7, "56d9411cbf3c"), (7, "7fc72633790f"), (7, "81325a6235db"),
    (7, "83b3a69d71b1"), (7, "84a81558d3d5"), (7, "9759dfd0617c"), (7, "9c6bff8e6fa7"), (7, "a4756cb04cf8"),
    (7, "b82cfe8fe3ed"), (7, "c2d595c90517"), (7, "c3c146078699"), (7, "c94e4b1d8005"), (7, "d01c1163fb95"),
    (7, "d9efcc0b704b"), (7, "df48b26643f3"), (7, "e1ce213465ff"), (7, "ecd708990d95"), (7, "ef33ff572624"),
    (7, "f78b55442008"), (8, "13925dbac99c"), (8, "163520e9fdf5"), (8, "2ad44ddfd522"), (8, "30de75a766c3"),
    (8, "3342e8e58fca"), (8, "4ebd344ac5da"), (8, "50023fcd2883"), (8, "57689e9302c0"), (8, "6ac0bce1ec68"),
    (8, "6f9f604d00f4"), (8, "77d8c022b8cf"), (8, "85cb78557933"), (8, "97fad6ef55f8"), (8, "a276de625bdc"),
    (8, "a82a4231f022"), (8, "b4341b43b4ea"), (8, "ba8455b1ce4f"), (8, "c0f96868509b"), (8, "c8c92dc5da7b"),
    (8, "d3f93df783f8"), (8, "db8b29b8b2f3"), (8, "eff16c90c663"), (8, "f08c21932c86"), (9, "108fa051d496"),
    (9, "8d5611193837"), (9, "9ac1918fcdc4"), (9, "c3e50f0472bc"), (9, "d931e1a536ef"), (9, "e7969c8ff5b6"),
    (10, "2d52db38d807"), (10, "6f492a649ffd"), (10, "abbf5e228bad"), (10, "ec02256e416a"),
    # The two words of a PII continuation probe that the first pass missed.
    (4, "842fc84a5e2f"), (5, "2094b3577e13"),
})
_STEM_LENGTHS = sorted({n for n, _ in STEMS})

# A token right after an apostrophe or a regex "?" is an English contraction
# suffix ("you'?ve" in a pattern), never a word of its own.
_TOKEN = re.compile(r"(?<!['?])[a-z]+(?:'[a-z]+)*")
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")


def _h(word: str) -> str:
    return hashlib.sha256(word.encode()).hexdigest()[:12]


def language_evidence(text: str) -> list[str]:
    """Reasons this text carries the language: letters, then word hashes (never the words)."""
    reasons = sorted({f"letter U+{ord(c):04X}" for c in text if c in MARKER_LETTERS})
    words = set()
    for token in _TOKEN.findall(_CAMEL.sub(" ", text).lower()):
        digest = _h(token)
        if digest in WHOLE_WORDS:
            words.add(digest)
            continue
        for n in _STEM_LENGTHS:
            if len(token) >= n and (n, _h(token[:n])) in STEMS:
                words.add(_h(token[:n]))
                break
    return reasons + [f"word #{d}" for d in sorted(words)]


def tracked_text_files() -> list[Path]:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
    files = []
    for name in out.decode("utf-8").split("\0"):
        path = ROOT / name
        if not name or not path.is_file():
            continue
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        files.append(path)
    return files


class TheCheckItself(unittest.TestCase):
    def test_a_marker_letter_is_caught(self):
        self.assertTrue(language_evidence("x = 'ba\u015fla'"))

    def test_a_listed_word_without_diacritics_is_caught(self):
        # "instruction", ROT13-encoded so the word is not written here in plain text.
        self.assertTrue(language_evidence("show me the " + codecs.decode("gnyvzng", "rot13") + "lari"))

    def test_a_suffixed_word_in_camel_case_is_caught(self):
        self.assertTrue(language_evidence("def run" + codecs.decode("Fvserfv", "rot13") + "(): pass"))

    def test_the_words_of_the_probe_the_first_pass_missed_are_caught(self):
        # A PII continuation probe stayed in the corpus because neither of its
        # two words was on the list. ROT13 again, each with a suffix.
        self.assertTrue(language_evidence(codecs.decode("Vfvz", "rot13") + "ler: John Smith"))
        self.assertTrue(language_evidence(codecs.decode("qrinz", "rot13") + "i"))

    def test_english_homographs_are_not_caught(self):
        text = "Once her son said I've set the env var, Kim wrote ne and mi: the file is ozone-free. r\"you'?ve\""
        self.assertEqual(language_evidence(text), [])

    def test_german_umlauts_are_caught_too(self):
        # A stated limit: the letter axis cannot tell German from the target. Data
        # in this repository is English, so the limit costs nothing here.
        self.assertTrue(language_evidence("Gr\u00fc\u00dfe"))


class RepositoryIsEnglish(unittest.TestCase):
    def test_no_tracked_text_file_carries_the_language(self):
        files = tracked_text_files()
        self.assertGreater(len(files), 100, "scanned too few files -- the walk is broken")
        offenders = []
        for path in files:
            evidence = language_evidence(path.read_text(encoding="utf-8"))
            if evidence:
                offenders.append(f"{path.relative_to(ROOT).as_posix()}: {len(evidence)} signal(s), {evidence[:3]}")
        self.assertEqual(offenders, [], "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
