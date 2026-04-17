# Deep View — 3-hour workshop

Welcome. This workshop is for working forensic investigators who are new to
programmatic, reproducible analysis. By the end of the three hours you will
have:

- installed Deep View on your laptop and verified the environment with
  `deepview doctor`;
- opened a raw memory dump, listed processes, and detected a synthetic
  rootkit;
- unlocked a synthetic LUKS volume and walked a FAT filesystem from an
  image;
- written a small custom plugin and loaded it through the plugin registry;
- left with a workbook full of real commands you can paste into your own
  environment tomorrow.

## Audience

You are a forensic analyst, incident responder, or SOC engineer who has
worked with GUI forensic suites (Autopsy, FTK, X-Ways, Volatility 2 via
`vol`) and wants to start using a CLI-first, scriptable toolkit.

You do **not** need:

- Prior Python experience (we will not ask you to write more than ~20 lines).
- Prior Volatility 3 experience (we will bridge from Volatility 2 idioms).
- A lab VM (we will run on your host; a recent Python 3.10+ is enough).

## Schedule

| Time  | Section                         | Format                            |
| ----- | ------------------------------- | --------------------------------- |
| 00:00 | Setup check, introductions      | Round the room                    |
| 00:15 | Forensic workflow & architecture | [Intro slides](intro.md)          |
| 00:45 | Exercise 1 — open a memory dump | Hands-on                          |
| 01:00 | Exercise 2 — list processes     | Hands-on                          |
| 01:15 | Short break                     |                                   |
| 01:25 | Exercise 3 — detect a rootkit   | Hands-on                          |
| 01:45 | Exercise 4 — unlock LUKS        | Hands-on                          |
| 02:00 | Exercise 5 — walk a FAT volume  | Hands-on                          |
| 02:20 | Exercise 6 — write a plugin     | Hands-on, paired                  |
| 02:50 | Q&A, roadmap, where to next     | Discussion                        |

All six exercises live in [exercises.md](exercises.md). A 90-minute
conference-talk version of the same material is outlined in
[slides-outline.md](slides-outline.md).

## Prerequisites

Before you arrive, install:

- Python 3.10 or newer (`python3 --version`).
- `git` (to clone the workshop repo).
- `pipx` or a virtual-env habit.
- Roughly 2 GB of free disk (sample images + analyser caches).

Optional but nice:

- `yara-python`, `volatility3` (installed automatically with the `memory`
  extra).
- A terminal with truecolor and the [Catppuccin Mocha](https://github.com/catppuccin/catppuccin)
  theme installed. Screenshots in the workbook are calibrated against that
  palette.

## Install

```bash
git clone <your-workshop-mirror-url> deepview
cd deepview
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,memory]'
deepview doctor
```

`deepview doctor` should print a table of PASS / WARN lines. WARN is fine;
FAIL on a required module is not. If you see FAIL, flag a facilitator.

## Sample data

The workshop ships three synthetic artefacts under `tests/fixtures/workshop/`:

- `mem-small.lime` — 512 MB Linux memory image with a tame process tree and
  one intentionally hidden PID (used for exercises 1-3).
- `luks-small.img` — a 64 MB LUKS1 volume; password is in the workbook
  (exercise 4).
- `fat32-small.img` — a 32 MB FAT32 image with a directory structure and a
  deliberately-deleted file (exercise 5).

None of these contain real PII. The hidden process in the memory image is a
synthetic `evil_daemon` placed there by the fixture generator.

## What you'll leave with

- A working Deep View install.
- A folder of scripts and custom plugins you wrote yourself.
- A map from the tasks you do in a GUI forensic suite to the equivalent CLI
  or Python idiom.
- A reading list: the [Architecture](../architecture/index.md),
  [Cookbook](../cookbook/index.md), and [Reference](../reference/index.md)
  sections of the main docs.
