import cffi
import glob
import shutil
import subprocess

def main():
    ffi = cffi.FFI()

    definitions = subprocess.check_output("gcc -E -P -I../src/ ../src/ptp/protocol/ptp_protocol.h", shell=True)  

    ffi.cdef(definitions.decode())
    ffi.set_source(
        "ptp_protocol",
        "#include <ptp/protocol/ptp_protocol.h>",
        sources=["../../src/ptp/protocol/ptp_encoding.c", "../../src/ptp/protocol/ptp_decoding.c"],
        include_dirs=["../../src/"],
    )

    ffi.compile(tmpdir="build", debug=True)

    for file in glob.glob(r"build/*.so"):
        print(file)
        shutil.copy(file, ".")

if __name__ == "__main__":
    main()
