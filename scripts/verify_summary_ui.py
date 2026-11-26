"""Exercise the portable window without a server. Only a reserved loopback port is used."""
import ctypes
from ctypes import wintypes
import hashlib
import json
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
user.SetForegroundWindow.argtypes = [wintypes.HWND]
user.IsChild.argtypes = [wintypes.HWND, wintypes.HWND]
user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user.GetWindowThreadProcessId.restype = wintypes.DWORD


def wait(predicate, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if result := predicate():
            return result
        time.sleep(.025)
    raise AssertionError("Window did not reach the expected state")


def find_window(pid, class_name="VipNetDiagnosticsWindow"):
    matches = []
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def visit(hwnd, unused):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        name = ctypes.create_unicode_buffer(80)
        user.GetClassNameW(hwnd, name, len(name))
        if owner.value == pid and name.value == class_name:
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

def verify_offline_game_addresses(win):
    games = json.loads((Path(__file__).resolve().parents[1] / "server/game-profiles.json").read_text("utf-8"))["profiles"]
    get = lambda i: user.GetDlgItem(win, i)
    send = lambda i, m, a=0, b=0: user.SendMessageW(get(i), m, a, b)
    def choose(control, index):
        assert send(control, 0x014E, index) == index
        user.SendMessageW(win, 0x0111, control | (1 << 16), get(control))
    send(206, 0x00F5)
    wait(lambda: send(313, 0x0146) == len(games), 30)
    for i, game in enumerate(games):
        choose(313, i)
        assert caption(get(313)) == game["name"]
        for region in game["regions"]:
            label = ctypes.create_unicode_buffer(region["label"])
            index = send(316, 0x0158, -1, ctypes.addressof(label))  # CB_FINDSTRINGEXACT
            assert index >= 0, region["label"]
            choose(316, index)
            assert caption(get(312)) == region["host"] and user.IsWindowEnabled(get(312)), (game["name"], region["label"], caption(get(312)), bool(user.IsWindowEnabled(get(312))))
        choose(316, send(316, 0x0146) - 1)
        assert caption(get(316)) == "Własny cel" and user.IsWindowEnabled(get(312))


def verify_archive(exe, origin, tmp):
    class Credential(ctypes.Structure):
        _fields_ = [("Flags",wintypes.DWORD),("Type",wintypes.DWORD),("TargetName",wintypes.LPWSTR),
                    ("Comment",wintypes.LPWSTR),("LastWritten",wintypes.FILETIME),("Size",wintypes.DWORD),
                    ("Blob",ctypes.c_void_p),("Persist",wintypes.DWORD),("Count",wintypes.DWORD),
                    ("Attributes",ctypes.c_void_p),("Alias",wintypes.LPWSTR),("UserName",wintypes.LPWSTR)]

    token = os.urandom(24).hex()
    origin += "/"  # Distinct Credential Manager target for the archive-only fixture.
    name = "VIP-NET/Diagnostics/" + origin
    cred = Credential()
    cred.Type, cred.TargetName, cred.Persist = 1, name, 1
    encoded = token.encode("utf-16-le")
    buf = ctypes.create_string_buffer(encoded)
    cred.Blob, cred.Size = ctypes.addressof(buf), len(encoded)
    store = ctypes.windll.advapi32
    # Never touch an existing Windows credential.
    existing = ctypes.c_void_p()
    if store.CredReadW(name, 1, 0, ctypes.byref(existing)):
        store.CredFree(existing)
        raise RuntimeError("Unexpected credential for ephemeral loopback URL")
    assert store.CredWriteW(ctypes.byref(cred), 0)
    try:
        key = hashlib.sha256((origin+"\n"+token).encode("utf-16-le")).hexdigest()
        archive = Path(tmp)/"VIP-NET"/"Diagnostyka"/key/"reports"
        archive.mkdir(parents=True)
        sid = "d165e424-71e1-4ef6-a853-6cc830238ae2"
        params = {"purpose":"mtr","profile_name":"MTR","target_name":"192.0.2.1"}
        doc = {"session_id":sid,"started_at":"2026-01-12T12:00:00Z","state":"cancelled",
               "measurement":params,"mtr_samples":[],"synchronized":False}
        (archive/(sid+".json")).write_text(json.dumps(doc),encoding="utf-8")
        cache = archive.parent.parent / ("games-" + hashlib.sha256(origin.encode("utf-16-le")).hexdigest() + ".json")
        cache.write_text(json.dumps({"version": 1, "profiles": [{"name":"Legacy", "regions":[], "processes":[]}]}), encoding="utf8")
        env = dict(os.environ, VIPNET_DESKTOP_ORIGIN=origin, LOCALAPPDATA=tmp)
        process = subprocess.Popen([str(exe)],env=env)
        win = None
        try:
            win = wait(lambda: find_window(process.pid))
            get = lambda i: user.GetDlgItem(win,i)
            click = lambda i: user.SendMessageW(get(i),0x00F5,0,0)
            # Creation exposes the HWND before the asynchronous credential/report restore completes.
            # A usable client-code control specifically acknowledges the seeded credential.
            wait(lambda: user.IsWindowVisible(win) and user.IsWindowEnabled(get(209))
                 and user.IsWindowEnabled(get(102)))
            verify_offline_game_addresses(win)
            for page, columns in ((209, 5), (210, 6)):
                click(page)
                header = user.SendMessageW(get(310), 0x101F, 0, 0)  # LVM_GETHEADER
                assert user.SendMessageW(header, 0x1200, 0, 0) == columns  # HDM_GETITEMCOUNT
            for keyboard in (True,False):
                # Navigation is setup; exercise the actual Enter and button activation below.
                user.SendMessageW(win, 0x0111, 209, get(209))
                wait(lambda: user.IsWindowVisible(get(310)) and user.SendMessageW(get(310),0x1004,0,0)==1
                     and user.IsWindowEnabled(get(330)))
                if keyboard:
                    user.SendMessageW(win,0x0028,get(310),1)
                    user.PostMessageW(get(310),0x0100,13,0)
                else:
                    click(330)
                wait(lambda: user.IsWindowVisible(get(315)))
                click(105)
                assert "192.0.2.1" in caption(get(112))
                click(108)
        finally:
            if win: user.PostMessageW(win,0x0010,0,0)
            process.wait(timeout=30)
    finally:
        assert store.CredDeleteW(name,1,0)


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
            click(250)
            details = wait(lambda: find_window(process.pid, "VipNetDetailsWindow"))
            popup_text = user.GetDlgItem(details, 401)
            assert "Komputer" in caption(popup_text)
            frame = bounds(details)
            assert frame.right - frame.left >= 560 and frame.bottom - frame.top >= 380
            assert caption(user.GetDlgItem(details, 402)) == "Kopiuj całość"
            if os.environ.get("CI") == "true":
                user.SendMessageW(user.GetDlgItem(details, 402), 0x00F5, 0, 0)
                kernel = ctypes.windll.kernel32
                user.GetClipboardData.argtypes = [wintypes.UINT]
                user.GetClipboardData.restype = wintypes.HANDLE
                kernel.GlobalLock.argtypes = [wintypes.HGLOBAL]
                kernel.GlobalLock.restype = ctypes.c_void_p
                kernel.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
                assert user.OpenClipboard(0)
                try:
                    data = user.GetClipboardData(13)
                    pointer = kernel.GlobalLock(data)
                    assert pointer
                    try:
                        assert "Komputer" in ctypes.wstring_at(pointer)
                    finally:
                        kernel.GlobalUnlock(data)
                finally:
                    user.CloseClipboard()
            user.SendMessageW(user.GetDlgItem(details, 403), 0x00F5, 0, 0)
            wait(lambda: not find_window(process.pid, "VipNetDetailsWindow"))
            for page in (202, 203):
                click(page)
                wait(lambda: user.IsWindowVisible(get(333)) and user.IsWindowEnabled(get(333)))
                assert user.IsWindowEnabled(get(332))
                assert bool(user.IsWindowVisible(get(334))) == (page == 202)
                if page == 202:
                    assert "Procent zajętej" in caption(get(311))
            click(108)

            for width, height in ((960, 640), (1366, 768), (1920, 1080)):
                user.SetWindowPos(win, 0, 0, 0, width, height, 0x16)
                rows = [bounds(get(i)) for i in (*range(240, 247), *range(250, 260), 261)]
                for row in rows:
                    assert row.right > row.left and row.bottom > row.top
                    assert row.bottom <= bounds(get(111)).top
                assert rows[0].right <= rows[1].left
                assert rows[1].bottom <= rows[2].top
            focus = get(101)
            class GuiThread(ctypes.Structure):
                _fields_ = [("size", wintypes.DWORD), ("flags", wintypes.DWORD)] + [
                    (name, wintypes.HWND) for name in ("active", "focus", "capture", "menu", "move", "caret")
                ] + [("rect", wintypes.RECT)]
            thread = user.GetWindowThreadProcessId(win, None)
            info = GuiThread()
            info.size = ctypes.sizeof(info)
            def focus_start_button():
                user.SetForegroundWindow(win)
                user.SendMessageW(win, 0x0028, focus, 1)  # WM_NEXTDLGCTL to the Start button
                return user.GetGUIThreadInfo(thread, ctypes.byref(info)) and info.focus == focus
            wait(focus_start_button)
            user.PostMessageW(focus, 0x0100, 9, 0)  # Tab through the actual dialog loop
            wait(lambda: user.GetGUIThreadInfo(thread, ctypes.byref(info))
                 and info.focus != focus and user.IsChild(win, info.focus))
            before = bounds(get(200))
            click(107)
            after = bounds(get(200))
            assert after.right - after.left < before.right - before.left
            assert caption(get(200)) == "Podsumowanie"
            click(211)
            assert user.IsWindowVisible(get(310)) and user.SendMessageW(get(310), 0x1004, 0, 0) == 5
            assert caption(get(331)) == "Sprawdź aktualizacje"
            for page in (1,2,3,4,5,7,8,9,10,11):
                click(200 + page)
                assert user.IsWindowVisible(get(310)) and not user.IsWindowVisible(get(112))
                assert bounds(get(310)).bottom <= bounds(get(311)).top
                assert bool(user.IsWindowVisible(get(331))) == (page == 11)
                assert bool(user.IsWindowVisible(get(315))) == (page in (7,8))
            verify_offline_game_addresses(win)
            click(108)
            assert not user.IsWindowVisible(get(112))
            user.SendMessageW(get(106), 0x014E, 1, 0)
            click(101)
            wait(lambda: user.IsWindowEnabled(get(101)) and user.IsWindowEnabled(get(105)), 40)
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
        verify_archive(exe,origin,tmp)
    print("Native summary, keyboard archive and open button, three window sizes, collapsed rail, settings, profile, offline and report passed")


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())
