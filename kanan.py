import frida
import glob
import sys
import getopt
import time
import os
from ctypes import *

# Called when a script sends us a message.
def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])


def usage():
    print("""
usage: python kanan.py <options>

    -h --help
        Displays this help text.

    -d --debug
        Runs each script in debug mode.

    -t --test
        Runs each script in testing mode where no patches should be applied.

    -p<id> --process <id>
        Attach kanan to a specific instance of mabi given by a process id.
    """)

def is_disabled(filename):
    if 'Defaults.js' in filename:
        return True
    with open('disabled.txt') as f:
        disabled_filenames = f.read()
    for disabled in disabled_filenames.splitlines():
        if len(disabled) > 0 and disabled.lower() in filename.lower():
            return True
    return False

def is_coalesced(filename):
    with open('coalesce.txt') as f:
        coalesced_filenames = f.read()
    for coalesced in coalesced_filenames.splitlines():
        if len(coalesced) > 0 and coalesced.lower() in filename.lower():
            return True
    return False

def is_delayed(filename):
    with open('delayed.txt') as f:
        delayed_filenames = f.read()
    for delayed in delayed_filenames.splitlines():
        if len(delayed) > 0 and delayed.lower() in filename.lower():
            return True
    return False

def main():
    # Handle command line arguments.
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hdp:t', ['help', 'debug', 'pid=', 'test'])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    debug_mode = 'false' 
    test_mode = 'false'
    pid = None 
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit()
        elif o in ('-d', '--debug'):
            debug_mode = 'true'
        elif o in ('-p', '--pid'):
            pid = int(a)
        elif o in ('-t', '--test'):
            test_mode = 'true'
        else:
            assert False, "Unhandled option"

    # Attach and load the scripts.
    print("Kanan's Mabinogi Mod")
    print("Waiting for Client.exe...")
    while windll.user32.FindWindowA(b'Mabinogi', b'Mabinogi') == 0:
        time.sleep(1)
    session = frida.attach('Client.exe' if pid is None else pid)
    print('Attached to Client.exe...')
    print('Loading scripts...')
    path = sys.path[0].replace('\\', '\\\\')
    script_defaults = 'var debug = {};\nvar testing = {};\nvar path = "{}";\n'.format(debug_mode, test_mode, path)
    scripts = []
    delayed_scripts = []
    with open('./scripts/Defaults.js') as f:
        script_defaults += f.read()
    coalesced_source = script_defaults
    for filename in glob.iglob('./scripts/*.js'):
        shortname = os.path.basename(filename)
        if is_disabled(filename):
            continue
        if is_delayed(filename):
            print("Delaying " + shortname)
            delayed_scripts.append(filename)
            continue
        source = script_defaults
        with open(filename) as f:
            if is_coalesced(filename) and debug_mode == 'false':
                print("Coalescing " + shortname)
                coalesced_source += f.read()
                continue
            else:
                print(shortname)
                source += f.read()
        script = session.create_script(source)
        script.on('message', on_message)
        script.load()
        scripts.append(script)
    # Execute the coalesced script.
    if debug_mode == 'false':
        print("Running coalesced script...")
        script = session.create_script(coalesced_source)
        script.on('message', on_message)
        script.load()
        scripts.append(script)
    # Execute delayed scripts.
    print("Running delayed scripts...")
    for filename in delayed_scripts:
        shortname = os.path.basename(filename)
        source = script_defaults
        with open(filename) as f:
            print(shortname)
            source += f.read()
        script = session.create_script(source)
        script.on('message', on_message)
        script.load()
        scripts.append(script)
    print("All done!")
    input()

    # Unload the scripts and detach.
    print("Unloading scripts (patches may stay applied)...")
    for script in scripts:
        script.unload()
    print("Detaching from Client.exe...")
    session.detach()

if __name__ == "__main__":
    main()
