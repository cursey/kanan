import frida
import glob

# Called when a script sends us a message.
def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

script_defaults = """
// Helper to scan for patterns in specific modules code section.
function scan(name, sig) {
    var ranges = Module.enumerateRangesSync(name, 'r-x');

    for (var i = 0; i < ranges.length; ++i) {
        var range = ranges[i];
        var results = Memory.scanSync(range.base, range.size, sig);

        if (results.length > 0) {
            return results[0].address;
        }
    }

    return NULL;
}
"""

print("Kanan's Mabinogi Mod")
print("Attaching to Client.exe...")

session = frida.attach('Client.exe')

print('Loading scripts...')

for filename in glob.iglob('./scripts/*.js'):
    print(filename)

    source = script_defaults

    with open(filename) as f:
        source += f.read()

    script = session.create_script(source)
    script.on('message', on_message)
    script.load()

session.detach()

print('All done!')
input()
