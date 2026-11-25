"""Exercise the portable window without a server. Only a reserved loopback port is used."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import winreg
from contextlib import contextmanager

user = ctypes.windll.user32
user.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
user.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user.SendMessageW.restype = ctypes.c_ssize_t
user.GetDlgItem.argtypes = [wintypes.HWND, ctypes.c_int]
user.GetDlgItem.restype = wintypes.HWND


def wait(predicate, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if result := predicate():
            return result
        time.sleep(.025)
    raise AssertionError("Window did not reach the expected state")


def find_window(pid):
    matches = []
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def visit(hwnd, unused):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        name = ctypes.create_unicode_buffer(80)
        user.GetClassNameW(hwnd, name, len(name))
        if owner.value == pid and name.value == "VipNetDiagnosticsWindow":
            matches.append(hwnd)
        return True

    user.EnumWindows(callback(visit), 0)
    return matches[0] if matches else None


def caption(hwnd):
    buf = ctypes.create_unicode_buffer(4096)
    user.SendMessageW(hwnd, 0x000D, len(buf), ctypes.addressof(buf))
    return buf.value


def bounds(hwnd):
    rect = wintypes.RECT()
    assert user.GetWindowRect(hwnd, ctypes.byref(rect))
    return rect


@contextmanager
def preserve_placement():
    key = r"Software\NetDiagnostics\Portable"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
            saved = winreg.QueryValueEx(handle, "Window")
    except FileNotFoundError:
        saved = None
    try:
        yield
    finally:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
            if saved is not None:
                winreg.SetValueEx(handle, "Window", 0, saved[1], saved[0])
            else:
                try:
                    winreg.DeleteValue(handle, "Window")
                except FileNotFoundError:
                    pass

def run(exe):
    with preserve_placement(), tempfile.TemporaryDirectory() as tmp, socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        origin = "https://127.0.0.1:" + str(reserved.getsockname()[1])
        env = dict(os.environ, VIPNET_DESKTOP_ORIGIN=origin, LOCALAPPDATA=tmp)
        process = subprocess.Popen([str(exe)], env=env)
        win = None
        try:
            win = wait(lambda: find_window(process.pid))
            get = lambda control: user.GetDlgItem(win, control)
            click = lambda control: user.SendMessageW(get(control), 0x00F5, 0, 0)
            wait(lambda: user.IsWindowEnabled(get(101)))
            assert not user.IsWindowVisible(get(112))
            assert user.SendMessageW(get(106), 0x0146, 0, 0) == 2
            assert "—" in caption(get(240))
            assert "Nie przetestowano" in caption(get(253))
            for width, height in ((960, 640), (1366, 768), (1920, 1080)):
                user.SetWindowPos(win, 0, 0, 0, width, height, 0x16)
                rows = [bounds(get(i)) for i in (*range(240, 247), *range(250, 260), 261)]
                for row in rows:
                    assert row.right > row.left and row.bottom > row.top
                    assert row.bottom <= bounds(get(111)).top
                assert rows[0].right <= rows[1].left
                assert rows[1].bottom <= rows[2].top
            focus = get(101)
            user.SendMessageW(win, 0x0028, focus, 1)  # WM_NEXTDLGCTL to a specific button
            class GuiThread(ctypes.Structure):
                _fields_ = [("size", wintypes.DWORD), ("flags", wintypes.DWORD)] + [
                    (name, wintypes.HWND) for name in ("active", "focus", "capture", "menu", "move", "caret")
                ] + [("rect", wintypes.RECT)]
            thread = user.GetWindowThreadProcessId(win, None)
            info = GuiThread()
            info.size = ctypes.sizeof(info)
            assert user.GetGUIThreadInfo(thread, ctypes.byref(info)) and info.focus == focus
            user.PostMessageW(focus, 0x0100, 9, 0)  # Tab through the actual dialog loop
            wait(lambda: user.GetGUIThreadInfo(thread, ctypes.byref(info)) and info.focus != focus)
            before = bounds(get(200))
            click(107)
            after = bounds(get(200))
            assert after.right - after.left < before.right - before.left
            assert caption(get(200)) == "Podsumowanie"
            click(211)
            assert user.IsWindowVisible(get(310)) and user.SendMessageW(get(310), 0x1004, 0, 0) == 4
            for page in (1,2,3,4,5,7,8,9,10,11):
                click(200 + page)
                assert user.IsWindowVisible(get(310)) and not user.IsWindowVisible(get(112))
                assert bounds(get(310)).bottom <= bounds(get(311)).top
                assert bool(user.IsWindowVisible(get(315))) == (page in (7,8))
            click(108)
            assert not user.IsWindowVisible(get(112))
            user.SendMessageW(get(106), 0x014E, 1, 0)
            click(101)
            wait(lambda: user.IsWindowEnabled(get(101)), 40)
            assert user.IsWindowEnabled(get(105))
            assert "—" in caption(get(240))
            click(105)
            assert "Sprawdź połączenie" in caption(get(112))
            click(105)
            assert origin in caption(get(112))
        finally:
            if win:
                user.PostMessageW(win, 0x0010, 0, 0)
            process.wait(timeout=50)
            assert process.returncode == 0
    print("Native summary, three window sizes, collapsed rail, settings, profile, offline and report passed")


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())
