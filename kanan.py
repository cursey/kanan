import frida
import glob
import sys
import getopt
import time
import os
from ctypes import *

def on_message(message, data):
    # Called when a script sends us a message.
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

def usage():
    # Prints usage information about how to use kanan.
    print("""
usage: python kanan.py <options>

    -h --help
        Displays this help text.

    -d --debug
        Runs each script in debug mode.

    -t --test
        Runs each script in testing mode where no patches should be applied.

    -v --verbose
        More information is output to the console by certain scripts.

    -p<id> --process <id>
        Attach kanan to a specific instance of mabi given by a process id.
    """)

def is_disabled(filename):
    # Determines if a filename has been disabled by the user.
    if 'Defaults.js' in filename:
        return True
    with open('disabled.txt') as f:
        disabled_filenames = f.read()
    for disabled in disabled_filenames.splitlines():
        if len(disabled) > 0 and disabled.casefold() in filename.casefold():
            return True
    return False

def is_coalesced(filename):
    # Determines if a filename is eligable to be coalesced according to the 
    # user.
    with open('coalesce.txt') as f:
        coalesced_filenames = f.read()
    for coalesced in coalesced_filenames.splitlines():
        if len(coalesced) > 0 and coalesced.casefold() in filename.casefold():
            return True
    return False

def is_delayed(filename):
    # Determines if a filename is to be loaded last by the user.
    with open('delayed.txt') as f:
        delayed_filenames = f.read()
    for delayed in delayed_filenames.splitlines():
        if len(delayed) > 0 and delayed.casefold() in filename.casefold():
            return True
    return False

class KananApp:
    def __init__(self):
        self.debug = 'false'
        self.test = 'false'
        self.verbose = 'false'
        self.pid = None
        self.path = sys.path[0].replace('\\', '\\\\')
        self.script_defaults = ''
        self.scripts = []

    def _parse_command_line(self):
        # Handle command line arguments.
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'hdp:tv', ['help', 'debug', 'pid=', 'test', 'verbose'])
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
            else:
                assert False, "Unhandled option"

    def _attach(self):
        # Attach to Mabinogi.
        while windll.user32.FindWindowA(b'Mabinogi', b'Mabinogi') == 0:
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
        self.session.detach()

    def _load_defaults(self):
        # Load Defaults.js and set additional variables that are available to
        # every loaded script.
        self.script_defaults = ('var debug = {};'
                           'var testing = {};'
                           'var verbose = {};'
                           'var path = "{}";').format(self.debug, self.test, self.verbose, self.path)
        with open('./scripts/Defaults.js') as f:
            self.script_defaults += f.read()

    def _run_script(self, source):
        # Run a single script and add it to the list of scripts.
        script = self.session.create_script(source)
        script.on('message', on_message)
        script.load()
        self.scripts.append(script)

    def _run_scripts(self):
        # Loads and runs all the scripts according to the settings.
        self._load_defaults()
        delayed_scripts = []
        coalesced_source = self.script_defaults
        for filename in glob.iglob('./scripts/*.js'):
            shortname = os.path.basename(filename)
            if is_disabled(filename):
                continue
            if is_delayed(filename):
                print("Delaying " + shortname)
                delayed_scripts.append(filename)
                continue
            with open(filename) as f:
                if is_coalesced(filename) and self.debug == 'false':
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
            self._run_script(self.coalesced_source)
        # Execute delayed scripts.
        print("Running delayed scripts...")
        for filename in delayed_scripts:
            shortname = os.path.basename(filename)
            with open(filename) as f:
                print("Running " + shortname)
                source = self.script_defaults
                source += 'var scriptName = "{}";\n'.format(shortname)
                source += f.read()
                self._run_script(source)

    def _unload_scripts(self):
        # Unloads all the loaded scripts and clears the loaded scripts list.
        for script in self.scripts:
            script.unload()
        self.scripts = []

    def run(self):
        # Runs kanan.
        self._parse_command_line()
        print("Kanan's Mabinogi Mod")
        print("Waiting for Client.exe...")
        self._attach()
        print("Attached to Client.exe...")
        print("Running scripts...")
        self._run_scripts()
        print("All done!")
        input()
        print("Unloading scripts (patches may stay applied)...")
        self._unload_scripts()
        print("Detaching from Client.exe...")
        self._detach()

def main():
    app = KananApp()
    app.run()

if __name__ == "__main__":
    main()
