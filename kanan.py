import frida
import glob
import sys
import getopt
import time
import os
import json
import tempfile
import shutil
import subprocess
import ctypes
from pathlib import Path


def usage():
    # Prints usage information about how to use kanan.
    print("""
usage: python kanan.py <options> [scripts]

    If [scripts] is empty then all scripts in the ./scripts directory will be
    loaded based on the current configuration.

    -h --help
        Displays this help text.

    -d --debug
        Runs each script in debug mode.

    -t --test
        Runs each script in testing mode where no patches should be applied.

    -v --verbose
        More information is output to the console by certain scripts.

    -a --all
        Run all scripts regardless of disabled.txt

    -p<id> --process <id>
        Attach kanan to a specific instance of mabi given by a process id.

    -s --start
        kanan will attempt to start mabi for you (useful for multi-client).
    """)


class KananApp:
    def __init__(self):
        self.debug = 'false'
        self.test = 'false'
        self.verbose = 'false'
        self.run_all = 'false'
        self.pid = None
        self.auto_start = False
        self.path = sys.path[0].replace('\\', '\\\\')
        self.script_defaults = ''
        self.scripts = []
        with open('disabled.txt') as f:
            self.disabled_filenames = f.read().splitlines()
        self.disabled_filenames.append('Defaults.js')
        with open('coalesce.txt') as f:
            self.coalesced_filenames = f.read().splitlines()
        with open('delayed.txt') as f:
            self.delayed_filenames = f.read().splitlines()
        self.scans = []
        self.scripts_to_load = []  # From the command line args.

    def on_message(self, message, data):
        # Called when a script sends us a message.
        if message['type'] == 'send':
            payload = message['payload']
            if type(payload) is dict:
                if 'signature' in payload:
                    self.scans.append(payload)
                elif 'file' in payload:
                    with open('./output/' + payload['file'], 'w') as f:
                        print(payload['data'], file=f)
            elif self.debug == 'true':
                print(time.strftime("%I:%M:%S ") + payload)
            else:
                print(payload)
        elif message['type'] == 'error':
            print(message['stack'])

    def is_disabled(self, filename):
        # Determines if a filename has been disabled by the user.
        if self.run_all == 'true':
            return 'Defaults.js'.casefold() in filename.casefold()
        if '.disabled' in filename:
            return True
        for disabled in self.disabled_filenames:
            if len(disabled) > 0 and disabled.casefold() in filename.casefold():
                return True
        return False

    def is_coalesced(self, filename):
        # Determines if a filename is eligible to be coalesced according to the
        # user.
        if '.coalesce' in filename:
            return True
        for coalesced in self.coalesced_filenames:
            if len(coalesced) > 0 and coalesced.casefold() in filename.casefold():
                return True
        return False

    def is_delayed(self, filename):
        # Determines if a filename is to be loaded last by the user.
        if '.delayed' in filename:
            return True
        for delayed in self.delayed_filenames:
            if len(delayed) > 0 and delayed.casefold() in filename.casefold():
                return True
        return False

    def _parse_command_line(self):
        # Handle command line arguments.
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'hdp:tvas', ['help', 'debug', 'pid=', 'test', 'verbose', 'all', 'start'])
        except getopt.GetoptError as err:
            print(err)
            usage()
            sys.exit(2)
        for o, a in opts:
            if o in ('-h', '--help'):
                usage()
                sys.exit()
            elif o in ('-d', '--debug'):
                self.debug = 'true'
            elif o in ('-p', '--pid'):
                self.pid = int(a)
            elif o in ('-t', '--test'):
                self.test = 'true'
            elif o in ('-v', '--verbose'):
                self.verbose = 'true'
            elif o in ('-a', '--all'):
                self.run_all = 'true'
            elif o in ('-s', '--start'):
                self.auto_start = True
            else:
                assert False, "Unhandled option"
        self.scripts_to_load = args

    def _attach(self):
        # Attach to Mabinogi.
        while ctypes.windll.user32.FindWindowA(b'Mabinogi', b'Mabinogi') == 0:
            time.sleep(1)
        try:
            self.session = frida.attach('Client.exe' if self.pid is None else self.pid)
        except frida.ProcessNotFoundError:
            print("Couldn't attach to Client.exe.")
            print("Make sure you're running kanan as administrator!")
            input()
            sys.exit()

    def _detach(self):
        # Detach from Mabinogi.
        try:
            self.session.detach()
        except:
            pass

    def _load_defaults(self):
        # Load Defaults.js and set additional variables that are available to
        # every loaded script.  The reason we don't load defaults in the
        # constructor is because we need to wait till the command line args
        # have been parsed.
        self.script_defaults = 'var debug = {};\n'.format(self.debug)
        self.script_defaults += 'var testing = {};\n'.format(self.test)
        self.script_defaults += 'var verbose = {};\n'.format(self.verbose)
        self.script_defaults += 'var path = "{}";\n'.format(self.path)
        with open('./scripts/Defaults.js') as f:
            self.script_defaults += f.read()

    def _run_script(self, source):
        # Run a single script and add it to the list of scripts.
        if self.debug == 'true':  # Prepend the results of every scan to the source
            source = 'var scans = {};\n'.format(json.dumps(self.scans)) + source
        script_loaded = False
        num_failed_load_attempts = 0
        while not script_loaded and num_failed_load_attempts < 3:
            try:
                script = self.session.create_script(source)
                script.on('message', self.on_message)
                script.load()
                script_loaded = True
            except frida.TransportError:
                print("Retrying...")
                num_failed_load_attempts += 1
        if script_loaded:
            self.scripts.append(script)
        else:
            print("Failed to load script!!!")

    def _run_scripts(self):
        # Loads and runs all the scripts according to the settings.
        self._load_defaults()
        # If we have a specific list of scripts to load from the command line
        # then load those and return.
        if self.scripts_to_load:
            for filename in self.scripts_to_load:
                shortname = os.path.basename(filename)
                with open(filename) as f:
                    source = self.script_defaults
                    source += 'var scriptName = "{}";\n'.format(shortname)
                    source += f.read()
                    self._run_script(source)
            return
        coalesced_source = self.script_defaults
        for filename in glob.iglob('./scripts/**/*.js', recursive=True):
            shortname = os.path.basename(filename)
            if self.is_disabled(filename) or self.is_delayed(filename):
                continue
            with open(filename) as f:
                if self.is_coalesced(filename) and self.debug == 'false':
                    print("Coalescing " + shortname)
                    coalesced_source += 'var scriptName = "{}";\n'.format(shortname)
                    coalesced_source += f.read()
                    continue
                else:
                    print("Running " + shortname)
                    source = self.script_defaults
                    source += 'var scriptName = "{}";\n'.format(shortname)
                    source += f.read()
                    self._run_script(source)
        # Execute the coalesced script.
        if self.debug == 'false':
            print("Running coalesced script...")
            self._run_script(coalesced_source)
        # Execute delayed scripts.
        print("Running delayed scripts...")
        for filename in glob.iglob('./scripts/**/*.js', recursive=True):
            shortname = os.path.basename(filename)
            if self.is_disabled(filename) or not self.is_delayed(filename):
                continue
            with open(filename) as f:
                print("Running " + shortname)
                source = self.script_defaults
                source += 'var scriptName = "{}";\n'.format(shortname)
                source += f.read()
                self._run_script(source)

    def _unload_scripts(self):
        # Unloads all the loaded scripts and clears the loaded scripts list.
        for script in self.scripts:
            try:
                script.unload()
            except:
                pass
        self.scripts = []

    def _process_alive(self, pid):
        # Checks if a process with the supplied pid is active.
        processes = [line.split() for line in subprocess.check_output('tasklist').splitlines()]
        # Skip the malformed entries at the beginning.
        [processes.pop(i) for i in [0, 1, 2]]
        pidstr = str(pid).encode('utf-8')
        for process in processes:
            if process[1] == pidstr:
                return True
        return False

    def _start_mabi(self):
        # Starts mabinogi if it can. Hopefully this can be improved so it
        # doesn't rely on the config files in the future.
        with open('directory.txt') as f:
            mabidir = Path(f.read().splitlines()[0])
        with open('args.txt') as f:
            args = f.read().splitlines()[0]
        if not mabidir.exists():
            print("Couldn't find Client.exe in " + str(mabidir))
            print("Please check directory.txt is correct.")
            print("Will wait for Client.exe to begin instead.")
            return None
        print("Starting Client.exe...")
        mabipath = str(mabidir)
        clientpath = str(mabidir / "Client.exe")
        # Try starting mabi.
        try:
            mabi = subprocess.Popen(clientpath + " " + args, cwd=mabipath)
        except OSError:
            print("Couldn't start Client.exe.")
            print("Make sure you're running kanan as administrator!")
            input()
            sys.exit()
        # Now we need to wait until mabi has been unpacked.
        # TODO: Figure out a better way please!!!
        time.sleep(1)
        return mabi.pid

    def run(self):
        # Runs kanan.
        self._parse_command_line()
        print("Kanan's Mabinogi Mod")
        if self.auto_start:
            self.pid = self._start_mabi()
        while True:
            print("Waiting for Client.exe...")
            self._attach()
            print("Attached to Client.exe...")
            print("Running scripts...")
            self._run_scripts()
            print("All done!")
            if self.pid:
                while self._process_alive(self.pid):
                    time.sleep(1)
            else:
                while ctypes.windll.user32.FindWindowA(b'Mabinogi', b'Mabinogi') != 0:
                    time.sleep(1)
            print("Unloading scripts (patches may stay applied)...")
            self._unload_scripts()
            print("Detaching from Client.exe...")
            self._detach()
            if self.pid:
                return


def cleanup_tmp_frida_trash():
    # Frida creates a new directory and extracts necessary files each time you
    # run it. They aren't necessary after the game closes/crashes so we can
    # delete them here.
    tempdir = Path(tempfile.gettempdir())
    for folder in glob.iglob(str(tempdir / 'frida*')):
        try:
            shutil.rmtree(folder)
        except PermissionError:
            pass


def main():
    cleanup_tmp_frida_trash()
    app = KananApp()
    app.run()

if __name__ == "__main__":
    main()
