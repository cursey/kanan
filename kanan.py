import frida
import glob
import sys
import getopt

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

def main():
    # Handle command line arguments.
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hdp:', ['help', 'debug', 'pid='])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    debug_mode = False
    pid = -1
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit()
        elif o in ('-d', '--debug'):
            debug_mode = True
        elif o in ('-p', '--pid'):
            pid = int(a)
        else:
            assert False, "Unhandled option"

    # Attach and load the scripts.
    print("Kanan's Mabinogi Mod")
    print("Attaching to Client.exe...")
    session = frida.attach('Client.exe' if pid == -1 else pid)
    print('Loading scripts...')
    script_defaults = 'var debug = {};\n'.format(str(debug_mode).lower())
    scripts = []
    with open('./scripts/Defaults.js') as f:
        script_defaults += f.read()
    for filename in glob.iglob('./scripts/*.js'):
        if is_disabled(filename):
            continue
        print(filename)
        source = script_defaults
        with open(filename) as f:
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
