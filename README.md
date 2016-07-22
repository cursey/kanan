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

You can attach kanan to different processes if you are running multiple clients. 
Open an adminstrator command prompt where `kanan.py` is located and run 
`python kanan.py -p<id>` where `id` is the process id you want to attach to. 

You can run `python kanan.py -h` for more usage information.

## Known issues
* The WindowsAppearFaster patch seems to cause crashes in certain locations. 
Disable it if you encounter this issue.
* Closing the command prompt after patches have been applied has caused crashes
for some users. If you experience a crash immediately after closing the command
prompt then leave it open for now.
    * If kanan.bat does not stay open then something is most likely wrong with
your python install.

## Original patch authors
Blade3575 
* Bitmap font
* Elf lag

Step29 
* NPC fast text
* One click revive
* Windows appear faster

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
