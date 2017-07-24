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
import toml
import psutil
from http import client
from hashlib import sha512
from binascii import hexlify
from base64 import b64encode
from json import loads, dumps
from subprocess import run, Popen, PIPE
from io import StringIO
from pathlib import Path


def get_login_passport():
    # Get something unique (not important as far as I can tell)
    cmd_result = run(['wmic', 'csproduct', 'get', 'uuid'], stdout=PIPE)
    cmd_result_str = StringIO(cmd_result.stdout.decode('utf-8'))

    # skip the first line
    cmd_result_str.readline()

    # Grab UUID
    uuid = cmd_result_str.readline().strip()

    # Ask for username/password.
    username = input("Username: ")
    password = input("Password: ")

    # Immediately convert it.
    password = hexlify(sha512(bytes(password, 'utf-8')).digest()).decode('utf-8')

    # First request.
    headers = {
        'User-Agent': 'NexonLauncher.nxl-17.04.01-290-621f8e0',
        'Content-Type': 'application/json'
    }
    body = {
        'id': username,
        'password': password,
        'auto_login': False,
        'client_id': '7853644408',
        'scope': 'us.launcher.all',
        'device_id': uuid
    }
    body_str = dumps(body)
    connection = client.HTTPSConnection('accounts.nexon.net', 443)

    connection.request('POST', '/account/login/launcher', body=body_str,
                       headers=headers)

    response = loads(connection.getresponse().read().decode('utf-8'))
    b64_token = b64encode(bytes(response['access_token'],
                                'utf-8')).decode('utf-8')

    # Second request.
    headers = {
        'User-Agent': 'NexonLauncher.nxl-17.04.01-290-621f8e0',
        'Cookie': 'nxtk=' + response['access_token'] +
                  ';domain=.nexon.net;path=/;',
        'Authorization': 'bearer ' + b64_token
    }
    connection = client.HTTPSConnection('api.nexon.io', 443)

    connection.request('GET', '/users/me/passport', headers=headers)
    response = loads(connection.getresponse().read().decode('utf-8'))

    # Return the passport.
    return response['passport']


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

    -m --morrighan
        kanan will attempt to start mabi with Morrighan for you.
    """)


class KananApp:
    def __init__(self):
        self.debug = 'false'
        self.test = 'false'
        self.verbose = 'false'
        self.run_all = 'false'
        self.pid = None
        self.session = None
        self.auto_start = False
        self.morrighan = False
        self.path = sys.path[0].replace('\\', '\\\\')
        self.script_defaults = ''
        self.scripts = []
        self.scans = []
        self.scripts_to_load = []  # From the command line args.
        with open('config.toml') as conf:
            config = conf.read()
        config += '\n'
        try:
            with open('private.toml') as conf:
                config += conf.read()
        except FileNotFoundError:
            pass
        self.config = toml.loads(config)

    def on_message(self, message, data):
        """Called when a script sends us a message."""
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict):
                if 'signature' in payload:
                    self.scans.append(payload)
                elif 'file' in payload:
                    with open('./output/' + payload['file'], 'w') as outfile:
                        print(payload['data'], file=outfile)
            elif self.debug == 'true':
                print(time.strftime("%I:%M:%S ") + payload)
            else:
                print(payload)
        elif message['type'] == 'error':
            print(message['stack'])

    def get_option(self, filename, option):
        """Retruns a mods option or None if it doesn't exist"""
        modname = os.path.splitext(os.path.basename(filename))[0]
        if modname in self.config:
            if option in self.config[modname]:
                return self.config[modname][option]
            else:
                print("NOTICE: " + modname + " is missing the '" + option +
                      "' entry in config.toml")
        else:
            print("NOTICE: " + modname + " does not have a config.toml entry")
            return None

    def is_disabled(self, filename):
        """Determines if a filename has been disabled by the user."""
        if self.run_all == 'true':
            return 'Defaults.js'.casefold() in filename.casefold()
        if '.disabled' in filename or 'Defaults.js' in filename:
            return True
        return self.get_option(filename, 'enable') is False

    def is_coalesced(self, filename):
        """Determines if a filename is eligible to be coalesced according to the
        user."""
        if '.coalesce' in filename:
            return True
        return self.get_option(filename, 'coalesce')

    def is_delayed(self, filename):
        """Determines if a filename is to be loaded last by the user."""
        if '.delayed' in filename:
            return True
        return self.get_option(filename, 'delay')

    def _parse_command_line(self):
        # Handle command line arguments.
        try:
            opts, args = getopt.getopt(sys.argv[1:],
                                       'hdp:tvasm',
                                       ['help', 'debug', 'pid=', 'test',
                                        'verbose', 'all', 'start',
                                        'morrighan'])
        except getopt.GetoptError as err:
            print(err)
            usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                usage()
                sys.exit()
            elif opt in ('-d', '--debug'):
                self.debug = 'true'
            elif opt in ('-p', '--pid'):
                self.pid = int(arg)
            elif opt in ('-t', '--test'):
                self.test = 'true'
            elif opt in ('-v', '--verbose'):
                self.verbose = 'true'
            elif opt in ('-a', '--all'):
                self.run_all = 'true'
            elif opt in ('-s', '--start'):
                self.auto_start = True
            elif opt in ('-m', '--morrighan'):
                self.morrighan = True
            else:
                assert False, "Unhandled option"
        self.scripts_to_load = args

    def _attach(self):
        # Attach to Mabinogi.
        while ctypes.windll.user32.FindWindowA(b'Mabinogi', None) == 0:
            time.sleep(1)
        try:
            self.session = frida.attach('Client.exe' if self.pid is None else
                                        self.pid)
            # Force the use of v8 for modern javascript (only for newer
            # versions of frida).
            enable_jit = getattr(self.session, 'enable_jit', None)
            if callable(enable_jit):
                enable_jit()
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
        cfg = json.dumps(self.config)
        self.script_defaults = 'var debug = {};\n'.format(self.debug)
        self.script_defaults += 'var testing = {};\n'.format(self.test)
        self.script_defaults += 'var verbose = {};\n'.format(self.verbose)
        self.script_defaults += 'var path = "{}";\n'.format(self.path)
        self.script_defaults += 'var config = {};\n'.format(cfg)
        with open('./scripts/Defaults.js') as defaults:
            self.script_defaults += defaults.read()

    def _script_specific_defaults(self, filename):
        # Returns defaults that need to be added to each script that are
        # specific to that script and therefor cannot be added to
        # self.script_defaults
        shortname = os.path.basename(filename)
        name = os.path.splitext(shortname)[0]
        scriptname = 'var scriptName = "{}";\n'.format(shortname)
        modname = 'var modName = "{}";\n'.format(name)
        return scriptname + modname

    def _run_script(self, source):
        # Run a single script and add it to the list of scripts.
        # Prepend the results of every scan to the source.
        if self.debug == 'true':
            scans = json.dumps(self.scans)
            source = 'var scans = {};\n'.format(scans) + source
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
                with open(filename) as script:
                    source = self.script_defaults
                    source += self._script_specific_defaults(filename)
                    source += script.read()
                    self._run_script(source)
            return
        coalesced_source = self.script_defaults
        for filename in glob.iglob('./scripts/**/*.js', recursive=True):
            shortname = os.path.basename(filename)
            if self.is_disabled(filename) or self.is_delayed(filename):
                continue
            with open(filename) as script:
                if self.is_coalesced(filename) and self.debug == 'false':
                    print("Coalescing " + shortname)
                    specific_defs = self._script_specific_defaults(filename)
                    coalesced_source += specific_defs
                    coalesced_source += script.read()
                    continue
                else:
                    print("Running " + shortname)
                    source = self.script_defaults
                    source += self._script_specific_defaults(filename)
                    source += script.read()
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
            with open(filename) as script:
                print("Running " + shortname)
                source = self.script_defaults
                source += self._script_specific_defaults(filename)
                source += script.read()
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
        processes = [line.split() for line in
                     subprocess.check_output('tasklist').splitlines()]
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
        mabidir = Path(self.get_option('AutoStart', 'directory'))
        args = self.get_option('AutoStart', 'args')
        passport = get_login_passport()
        args = args + ' /P:' + passport
        if not mabidir.exists():
            print("Couldn't find Client.exe in " + str(mabidir))
            print("Please make sure the directory is correct in config.toml")
            print("Will wait for Client.exe to begin instead.")
            return None
        mabipath = str(mabidir)
        if self.morrighan:
            print("Starting Morrighan.exe...")
            clientpath = str(mabidir / "Morrighan.exe")
        else:
            print("Starting Client.exe...")
            clientpath = str(mabidir / "Client.exe")
        # Try starting mabi.
        try:
            subprocess.Popen(clientpath + " " + args, cwd=mabipath)
        except OSError:
            print("Couldn't start Client.exe.")
            print("Make sure you're running kanan as administrator!")
            input()
            sys.exit()
        # Now we need to wait until mabi has been unpacked.
        # TODO: Figure out a better way please!!!
        time.sleep(1)
        return get_newest_client_pid()

    def run(self):
        """Runs kanan."""
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
                while ctypes.windll.user32.FindWindowA(b'Mabinogi', None) != 0:
                    time.sleep(1)
            print("Unloading scripts (patches may stay applied)...")
            self._unload_scripts()
            print("Detaching from Client.exe...")
            self._detach()
            if self.pid:
                return


def cleanup_tmp_frida_trash():
    """Frida creates a new directory and extracts necessary files each time you
    run it. They aren't necessary after the game closes/crashes so we can
    delete them here."""
    tempdir = Path(tempfile.gettempdir())
    for folder in glob.iglob(str(tempdir / 'frida*')):
        try:
            shutil.rmtree(folder)
        except PermissionError:
            pass


def get_newest_client_pid():
    """Searches through all the Client.exe's to find the newest one.
    Returns -1 if Client.exe is not found."""
    time = 0
    pid = -1
    for proc in psutil.process_iter():
        if proc.name() == 'Client.exe':
            if time < proc.create_time():
                time = proc.create_time()
                pid = proc.pid
    return pid


def main():
    """The entrypoint for kanan"""
    cleanup_tmp_frida_trash()
    app = KananApp()
    app.run()


if __name__ == "__main__":
    main()
