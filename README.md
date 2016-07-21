# kanan
Mods for Mabinogi using Javascript

## Instructions
1. Download Python 3 from [python.org](https://www.python.org/downloads/). 
2. While installing it make sure you check the box that says **Add Python 3.x to
PATH**
3. To make sure Python was installed correctly, open a command prompt and type
`python --version` and you should get a response.
4. Start Mabinogi.
5. Run the batch file `kanan.bat` as an administrator.

## Things to be aware of
By default every script (mod) that comes with kanan is enabled. To disable a 
mod go into the `./scripts/` directory and delete it, or add the name of the 
feature (BitmapFont for example) to `disabled.txt`.

## Known issues
* The WindowsAppearFaster patch seems to cause crashes in certain locations. 
Disable it if you encounter this issue.

## Credits
* Credits to Blade3575 for the bitmap font and elf lag patches.
* Credits to Step29 for the NPC fast text, one click revive and windows appear 
faster patches.

## Contributing
Contributions are welcome. If you are contributing a patch that you aren't the
original author of please give credits at the top of the file. If a patch has 
been added and you are the original author of it or know who is, open an issue
so proper credits may be given (or issue a pull request).

## Contributions
Patches provided by QewQew
* ElfLagFix
* NPCFastText
* OneClickRevive
* WindowsAppearFaster

Thanks to all contributors!
