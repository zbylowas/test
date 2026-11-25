"""Check the icon groups that Windows reads from the release EXE."""
import ctypes
import struct
import sys
from pathlib import Path


def verify(exe):
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    api.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, pointer, ctypes.c_uint]
    api.LoadLibraryExW.restype = pointer
    api.FreeLibrary.argtypes = [pointer]
    for name, args in (("FindResourceW", [pointer, pointer, pointer]), ("LoadResource", [pointer, pointer]),
                       ("LockResource", [pointer]), ("SizeofResource", [pointer, pointer])):
        fn = getattr(api, name)
        fn.argtypes = args
        fn.restype = ctypes.c_uint32 if name == "SizeofResource" else pointer
    module = api.LoadLibraryExW(str(exe.resolve()), None, 2)  # LOAD_LIBRARY_AS_DATAFILE
    if not module:
        raise ctypes.WinError(ctypes.get_last_error())
    def resource(name, kind):
        handle = api.FindResourceW(module, name, kind)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        address = api.LockResource(api.LoadResource(module, handle))
        return ctypes.string_at(address, api.SizeofResource(module, handle))
    try:
        signatures = set()
        for group_id in [1, *range(20, 41)]:
            group = resource(group_id, 14)
            reserved, kind, count = struct.unpack_from("<3H", group)
            assert (reserved, kind) == (0, 1)
            frames = {}
            for i in range(count):
                width, height, _, _, _, _, length, image_id = struct.unpack_from("<4B2H I H", group, 6 + i*14)
                image = resource(image_id, 3)
                assert width == height and len(image) == length and image.startswith(b"\x89PNG\r\n\x1a\n")
                frames[width or 256] = image
            assert {16, 32, 48}.issubset(frames)
            if group_id == 1:
                assert 256 in frames
            else:
                signatures.add(frames[32])
        assert len(signatures) == 21
    finally:
        api.FreeLibrary(module)
    print("Verified the Explorer icon and 21 distinct live Win32 icon positions.")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
