# How the detector's threshold was chosen

The [README](../README.md#how-the-detector-is-measured) gives the headline measurement and
the command that reproduces it. This page holds the two findings behind it.

## The retracted in-sample number

The README used to quote "100% F1". The number was real but it measured memorisation:
`train()` and `benchmark()` drew from the same two sources, so the model was being
examined on its own study notes. `benchmark()` still exists and still returns 1.00. It now
labels itself `in_sample` and says which method to call instead.

## The calibration bug

Measuring on a holdout surfaced a calibration bug worth naming. At the old default
threshold of 0.50, holdout F1 was 0.110 with recall 0.058, meaning about 182 of 193
attacks got through. The cause is in the layer weights: on a payload the model has not
seen, the regex layer usually contributes 0.0 (its patterns know a narrow set of stock
phrasings; on one holdout fold it scored 0.0 for 36 of 39 unseen payloads), so even a
strong TF-IDF signal of 0.80 tops out at 0.39 weighted and never clears 0.50. In-sample
scoring cannot reveal this, because there every threshold scores 1.00.

## The threshold sweep

The default is now 0.30, chosen from a sweep across four seeds (1337, 42, 7, 2026;
re-measured 2026-09-24 on the 193-probe English attack corpus):

| Threshold | F1 | Recall | Precision | False positives (of 80 benign) |
|---|---|---|---|---|
| 0.50 (old) | 0.110 | 0.058 | 1.000 | 0.0 |
| 0.32 | 0.872 | 0.780 | 0.990 | 1.5 |
| 0.30 (default) | 0.932 | 0.883 | 0.986 | 2.5 |
| 0.28 | 0.954 | 0.930 | 0.978 | 4.0 |
| 0.25 | 0.959 | 0.979 | 0.940 | 12.0 |
| 0.20 | 0.923 | 0.996 | 0.860 | 31.25 |

F1 peaks nearer 0.25, but in an input filter a false positive is a blocked legitimate
request, so 0.30 keeps precision at 0.99 while taking recall from 0.058 to 0.883. Pass
`threshold=0.25` for a more aggressive posture. The trade is in the table rather than left
to guesswork.
