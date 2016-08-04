# Kanan's Mabinogi Mod
Mods for Mabinogi using JavaScript

## Instructions
1. Download Python 3 from [python.org](https://www.python.org/downloads/).
2. While installing it make sure you check the box that says **Add Python 3.x to
PATH**
3. To make sure Python was installed correctly, open a command prompt and type
`python --version` and you should get a response.
4. Run the batch file `kanan.bat` as an administrator.

You can run `python kanan.py -h` for more usage information. For best results,
run kanan before launching mabi and keep it running in the background.

## Features
Look in the scripts directory for a full list of mods provided with kanan.
* By default most scripts (mods) that come with kanan are enabled. To disable a
mod go into the `./scripts/` directory and delete it, or add the name of the
feature (BitmapFont for example) to `disabled.txt`.
* You can attach kanan to different processes if you are running multiple
clients. Open an administrator command prompt where `kanan.py` is located and
run `python kanan.py -p<id>` where `id` is the process id you want to attach to.
* You can use kanan to load dll's into mabi by modifying `DllLoader.js`. More
details on what to do are located at the top of that file.
* You can use kanan's data folder as if it was mabi's data folder for file based
mods. Read `UseDataFolder.js` for more detail. Essentially this feature
redirects mabi's data folder, to the data folder `kanan.py` is in allowing you
to fully mod mabi without touching its folder.
* Simple scripts can be automatically coalesced to cut down on memory usage.
* `PatternScanSnapshot.js` automatically disassembles the locations of patterns
used by each script for archiving and easier updating when something breaks.

## Known issues
* Closing the command prompt after patches have been applied has caused crashes
for some users. If you experience a crash immediately after closing the command
prompt then leave it open for now.
    * If `kanan.bat` does not stay open then something is most likely wrong with
your python install.

## Contributing
Contributions are welcome. If you are contributing a patch that you aren't the
original author of please give credits at the top of the file. If a patch has
been added and you are the original author of it or know who is, open an issue
so proper credits may be given (or issue a pull request).

## Original patch authors
* Blade3575
    * Bitmap font
    * Elf lag
* Step29
    * NPC fast text
    * One click revive
    * Free indoor camera
    * Hide NPC curtains
    * Hide second title
    * No player zoom transparency
    * Mana tunnel lag fix
    * No skill rank up window
    * Windows appear faster
* Rydian
    * No black bars
    * Transformation mastery collect mode always enabled
    * No persistent fighter chain popup
    * Objects between camera and character do not become transparent
    * Client side devCat title

## Thank you to all contributors!
* QewQew
* C0ZIEST
* Kyralis
