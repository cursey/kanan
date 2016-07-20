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

usage_text = """
usage: python kanan.py <options>

    -h --help
        displays this help text

    -d --debug
        runs in debug mode
"""

def usage():
    print(usage_text)

def is_disabled(filename):
    with open('disabled.txt') as f:
        disabled_filenames = f.read()
    for disabled_filename in disabled_filenames.splitlines():
        if disabled_filename in filename:
            return True;
    return False;

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hd', ['help', 'debug'])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    debug_mode = False
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit()
        elif o in ('-d', '--debug'):
            debug_mode = True
        else:
            assert False, "Unhandled option"
    print("Kanan's Mabinogi Mod")
    print("Attaching to Client.exe...")
    session = frida.attach('Client.exe')
    print('Loading scripts...')
    script_defaults = 'var debug = {};\n'.format(str(debug_mode).lower())
    with open('./scripts/Defaults.js') as f:
        script_defaults += f.read()
    for filename in glob.iglob('./scripts/*.js'):
        if 'Defaults.js' in filename or is_disabled(filename):
            continue
        print(filename)
        source = script_defaults
        with open(filename) as f:
            source += f.read()
        script = session.create_script(source)
        script.on('message', on_message)
        script.load()
    print('All done!')
    input()

if __name__ == "__main__":
    main()
