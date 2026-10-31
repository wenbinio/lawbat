"""
The JavaScript<->Python bridge exposed into the pywebview window.

The web page can't read a real folder path from the OS, so the one thing we
must surface natively is the folder picker. Everything else goes through the
localhost HTTP API. Keeping this surface tiny preserves the egress story: the
window is a native frame, not a browser, with no URL bar and no general file
access beyond what the user explicitly picks.

COM STA + the bridge thread (C5)
--------------------------------
pywebview invokes ``js_api`` methods (like ``pick_folder``) on a BACKGROUND
"bridge" thread, NOT the main GUI thread that called ``webview.start()``. On
Windows that breaks a native folder dialog two ways:

* pywebview's Windows backend (``platforms/winforms.py``) runs the dialog with a
  bare ``ShowDialog()`` on the *calling* thread — it does NOT marshal onto the UI
  thread (verified in the pywebview source: no ``Invoke``/semaphore there, unlike
  ``get_cookies``). So the dialog runs on our bridge thread, off the GUI/STA
  thread.
* The Win32 folder/file pickers (``IFileOpenDialog`` / the shell ``SHBrowseFor‐
  Folder`` family) are COM apartment-affine and want a Single-Threaded-Apartment
  thread. On the wrong apartment they return nothing or hang — the shipped
  Windows picker never opens.

pywebview exposes NO public "run this Python callable on the GUI thread"
dispatcher (confirmed against the docs + source: ``start(func)`` even runs
``func`` on its OWN thread, not the main one; only the native event loop is on
the main thread, reachable solely through backend-internal ``form.Invoke`` which
is not a stable public surface). So rather than fight pywebview's threading, on
Windows we drive the folder picker DIRECTLY through the Win32 shell API on a
dedicated thread we initialise as COM STA ourselves (stdlib ``ctypes`` only — no
new dependency, no pywebview-version coupling). That call is apartment-correct by
construction. Off Windows we keep pywebview's ``create_file_dialog`` (its GTK /
Cocoa backends handle this path fine, and that is what shipped working there).
"""

import sys
import threading


class DesktopApi:
    def __init__(self):
        self._window = None

    def set_window(self, window):
        self._window = window

    def pick_folder(self):
        """Open a native 'choose folder' dialog. Returns the path or None.

        Called on pywebview's background bridge thread. On Windows we marshal the
        dialog onto a dedicated COM-STA thread (see module docstring); elsewhere we
        defer to pywebview's own dialog. The dev-browser path (no native window)
        keeps falling through to ``None`` so the page can prompt instead.
        """
        if sys.platform == "win32":
            return _pick_folder_win32_sta()
        return self._pick_folder_pywebview()

    def _pick_folder_pywebview(self):
        """Non-Windows path: use pywebview's native dialog (unchanged behaviour).

        Returns None when there is no native window (dev browser) so the caller
        falls back to the in-page prompt.
        """
        import webview

        if self._window is None:
            return None
        result = self._window.create_file_dialog(webview.FOLDER_DIALOG)
        if not result:
            return None
        # pywebview returns a tuple/list of selected paths.
        return result[0] if isinstance(result, (list, tuple)) else result

    def pick_files(self):
        """Open a native MULTI-SELECT 'choose files' dialog. Returns a list of
        paths (possibly empty) or None on cancel.

        Multi-source ingestion (adding a picked set of files into the matter). Same
        threading story as pick_folder: on Windows we drive the COM IFileOpenDialog
        with FOS_ALLOWMULTISELECT on a dedicated COM-STA thread; elsewhere we use
        pywebview's OPEN_DIALOG with allow_multiple=True. The dev-browser path (no
        native window) returns None so the page can prompt instead.
        """
        if sys.platform == "win32":
            return _pick_files_win32_sta()
        return self._pick_files_pywebview()

    def _pick_files_pywebview(self):
        """Non-Windows multi-file path: pywebview's native open dialog."""
        import webview

        if self._window is None:
            return None
        result = self._window.create_file_dialog(
            webview.OPEN_DIALOG, allow_multiple=True)
        if not result:
            return None
        # pywebview returns a tuple/list of selected paths.
        return list(result) if isinstance(result, (list, tuple)) else [result]


def _pick_folder_win32_sta():
    """Run the Windows folder picker on a dedicated COM-STA thread, block, return.

    The bridge thread that calls ``pick_folder`` is NOT a usable COM-STA thread, so
    we spin up a short-lived thread, initialise COM as a Single-Threaded Apartment
    ON THAT THREAD, show the shell folder dialog there, and hand the result back via
    a slot + ``Event``. This is the "marshal the dialog onto a correctly-initialised
    main/STA thread and block for the result" shape the dialog needs on Windows.

    Uses only stdlib ``ctypes`` against ole32/shell32 (no new dependency). Returns
    the selected path, or None on cancel / any failure (never raises — a failed
    picker must degrade to "no folder chosen", not crash the bridge).
    """
    result_slot = {"path": None}
    done = threading.Event()

    def _worker():
        try:
            result_slot["path"] = _shell_browse_for_folder()
        except Exception:
            # A failed dialog must not take down the bridge thread; degrade to None.
            result_slot["path"] = None
        finally:
            done.set()

    t = threading.Thread(target=_worker, name="folder-dialog-sta", daemon=True)
    t.start()
    # Block the bridge thread until the dialog closes; generous bound so a user who
    # leaves the dialog open isn't cut off, but a wedged call can't hang forever.
    done.wait(timeout=600)
    return result_slot["path"]


def _shell_browse_for_folder():
    """Show the Win32 shell 'choose folder' dialog on the CURRENT thread.

    MUST be called on a thread initialised as COM STA (see ``_pick_folder_win32_sta``).
    Returns the chosen absolute path, or None on cancel/error. ctypes-only.

    Uses ``SHBrowseForFolderW`` + ``SHGetPathFromIDListW`` (the classic shell folder
    picker): compact, dependency-free, and apartment-correct once COM is STA-init'd
    on this thread.
    """
    import ctypes
    from ctypes import wintypes

    ole32 = ctypes.windll.ole32
    shell32 = ctypes.windll.shell32

    # COINIT_APARTMENTTHREADED = 0x2. CoInitializeEx returns S_OK (0) or S_FALSE (1)
    # if already initialised on this thread; RPC_E_CHANGED_MODE means a different
    # apartment was already set — in that case we must NOT call CoUninitialize.
    COINIT_APARTMENTTHREADED = 0x2
    S_OK = 0
    S_FALSE = 1
    hr = ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
    # Pair CoUninitialize with CoInitializeEx ONLY when it actually SUCCEEDED on this
    # thread (#25). MSDN: every SUCCESSFUL CoInitializeEx — including S_FALSE (already
    # init'd, refcount bumped) — must be balanced by exactly one CoUninitialize; a
    # FAILED call (RPC_E_CHANGED_MODE, or any other error HRESULT) must NOT be. The old
    # `hr not in (RPC_E_CHANGED_MODE,)` treated every NON-changed-mode error as success
    # and would CoUninitialize after a failed init (an unbalanced call that can corrupt
    # the apartment refcount). Gate strictly on the documented success values.
    com_initialized_here = hr in (S_OK, S_FALSE)

    try:
        # BROWSEINFOW: we only need the flags + a buffer for the returned name; we
        # read the true path back from the returned PIDL via SHGetPathFromIDListW.
        BIF_RETURNONLYFSDIRS = 0x00000001  # filesystem dirs only (no virtual nodes)
        BIF_NEWDIALOGSTYLE = 0x00000040  # resizable, "Make New Folder", proper modern UI
        BIF_EDITBOX = 0x00000010  # let the user type/paste a path

        class BROWSEINFOW(ctypes.Structure):
            _fields_ = [
                ("hwndOwner", wintypes.HWND),
                ("pidlRoot", ctypes.c_void_p),
                ("pszDisplayName", wintypes.LPWSTR),
                ("lpszTitle", wintypes.LPCWSTR),
                ("ulFlags", wintypes.UINT),
                ("lpfn", ctypes.c_void_p),
                ("lParam", wintypes.LPARAM),
                ("iImage", ctypes.c_int),
            ]

        display_buf = ctypes.create_unicode_buffer(260)  # MAX_PATH
        bi = BROWSEINFOW()
        bi.hwndOwner = None
        bi.pidlRoot = None
        bi.pszDisplayName = ctypes.cast(display_buf, wintypes.LPWSTR)
        bi.lpszTitle = "Choose the exported data-room folder"
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX
        bi.lpfn = None
        bi.lParam = 0
        bi.iImage = 0

        # Returns a PIDL (LPITEMIDLIST) the caller must free with CoTaskMemFree.
        shell32.SHBrowseForFolderW.restype = ctypes.c_void_p
        pidl = shell32.SHBrowseForFolderW(ctypes.byref(bi))
        if not pidl:
            return None  # user cancelled

        try:
            path_buf = ctypes.create_unicode_buffer(32768)  # generous for long paths
            shell32.SHGetPathFromIDListW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR]
            shell32.SHGetPathFromIDListW.restype = wintypes.BOOL
            ok = shell32.SHGetPathFromIDListW(pidl, path_buf)
            if not ok:
                return None
            path = path_buf.value
            return path or None
        finally:
            ole32.CoTaskMemFree(pidl)
    finally:
        # Balance CoInitializeEx only when WE established the apartment on this
        # thread; never uninitialise an apartment we didn't create.
        if com_initialized_here:
            try:
                ole32.CoUninitialize()
            except Exception:
                pass


def _pick_files_win32_sta():
    """Run the Windows MULTI-SELECT file picker on a dedicated COM-STA thread,
    block, return the chosen paths (a list, possibly empty) or None on cancel.

    Same shape as _pick_folder_win32_sta (the bridge thread is not COM-STA, so we
    marshal onto a short-lived STA thread). Never raises — a failed dialog degrades
    to None.
    """
    result_slot = {"paths": None}
    done = threading.Event()

    def _worker():
        try:
            result_slot["paths"] = _shell_open_files_multi()
        except Exception:
            result_slot["paths"] = None
        finally:
            done.set()

    t = threading.Thread(target=_worker, name="files-dialog-sta", daemon=True)
    t.start()
    done.wait(timeout=600)
    return result_slot["paths"]


def _shell_open_files_multi():
    r"""Show the Win32 IFileOpenDialog with FOS_ALLOWMULTISELECT on the CURRENT
    thread (must be COM-STA — see _pick_files_win32_sta). Returns a list of chosen
    absolute paths, or None on cancel/error. ctypes-only (no new dependency).

    The modern common-item dialog (IFileOpenDialog) is the supported multi-select
    open dialog; we drive its vtable through ctypes function pointers.
    """
    import ctypes
    from ctypes import wintypes

    ole32 = ctypes.windll.ole32

    COINIT_APARTMENTTHREADED = 0x2
    S_OK = 0
    S_FALSE = 1
    hr = ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
    # Balance CoUninitialize with a SUCCESSFUL CoInitializeEx only (#25 — see
    # _shell_browse_folder): S_OK / S_FALSE are the documented success values that must
    # be balanced; any error HRESULT (RPC_E_CHANGED_MODE or otherwise) must NOT call
    # CoUninitialize.
    com_initialized_here = hr in (S_OK, S_FALSE)

    # CLSID_FileOpenDialog {DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7} and
    # IID_IFileOpenDialog {D57C7288-D4AD-4768-BE02-9D969532D960}.
    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    def _guid(d1, d2, d3, d4):
        g = GUID()
        g.Data1, g.Data2, g.Data3 = d1, d2, d3
        for i, b in enumerate(d4):
            g.Data4[i] = b
        return g

    CLSID_FileOpenDialog = _guid(
        0xDC1C5A9C, 0xE88A, 0x4DDE,
        (0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7))
    IID_IFileOpenDialog = _guid(
        0xD57C7288, 0xD4AD, 0x4768,
        (0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60))

    CLSCTX_INPROC_SERVER = 0x1
    FOS_ALLOWMULTISELECT = 0x00000200
    FOS_FORCEFILESYSTEM = 0x00000040
    FOS_FILEMUSTEXIST = 0x00001000
    SIGDN_FILESYSPATH = 0x80058000

    def _vtbl_call(p_obj, index, restype, argtypes, *args):
        # p_obj points at the COM object; *p_obj is the vtable; vtable[index] is the
        # method. Build a callable from the function pointer and invoke it.
        vtbl = ctypes.cast(p_obj, ctypes.POINTER(ctypes.c_void_p))
        fn_ptr = ctypes.cast(vtbl[0], ctypes.POINTER(ctypes.c_void_p))[index]
        proto = ctypes.WINFUNCTYPE(restype, *argtypes)
        return proto(fn_ptr)(p_obj, *args)

    paths = None
    p_dialog = ctypes.c_void_p()
    try:
        hr = ole32.CoCreateInstance(
            ctypes.byref(CLSID_FileOpenDialog), None, CLSCTX_INPROC_SERVER,
            ctypes.byref(IID_IFileOpenDialog), ctypes.byref(p_dialog))
        if hr != 0 or not p_dialog:
            return None

        # IFileOpenDialog vtable layout (IUnknown 0-2, IModalWindow Show=3,
        # IFileDialog: SetFileTypes=4 … GetOptions=9, SetOptions=10, … Show is at 3).
        # Indices for the methods we use:
        #   3  Show(HWND)
        #   9  GetOptions(DWORD*)
        #   10 SetOptions(DWORD)
        #   GetResults is IFileOpenDialog-specific at vtable index 27,
        #   IUnknown::Release is index 2.
        IDX_RELEASE = 2
        IDX_SHOW = 3
        IDX_GETOPTIONS = 9
        IDX_SETOPTIONS = 10
        IDX_GETRESULTS = 27

        opts = wintypes.DWORD(0)
        _vtbl_call(p_dialog, IDX_GETOPTIONS, ctypes.HRESULT,
                   [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)], ctypes.byref(opts))
        new_opts = (opts.value | FOS_ALLOWMULTISELECT
                    | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST)
        _vtbl_call(p_dialog, IDX_SETOPTIONS, ctypes.HRESULT,
                   [ctypes.c_void_p, wintypes.DWORD], wintypes.DWORD(new_opts))

        hr = _vtbl_call(p_dialog, IDX_SHOW, ctypes.HRESULT,
                        [ctypes.c_void_p, wintypes.HWND], None)
        if hr != 0:
            return None  # cancelled (HRESULT_FROM_WIN32(ERROR_CANCELLED)) or error

        p_results = ctypes.c_void_p()
        hr = _vtbl_call(p_dialog, IDX_GETRESULTS, ctypes.HRESULT,
                        [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
                        ctypes.byref(p_results))
        if hr != 0 or not p_results:
            return None

        try:
            # IShellItemArray::GetCount (index 7) + GetItemAt (index 8).
            count = wintypes.DWORD(0)
            _vtbl_call(p_results, 7, ctypes.HRESULT,
                       [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)],
                       ctypes.byref(count))
            out = []
            for i in range(count.value):
                p_item = ctypes.c_void_p()
                hr = _vtbl_call(p_results, 8, ctypes.HRESULT,
                                [ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(ctypes.c_void_p)],
                                wintypes.DWORD(i), ctypes.byref(p_item))
                if hr != 0 or not p_item:
                    continue
                try:
                    # IShellItem::GetDisplayName (index 5) -> a co-task-mem LPWSTR.
                    p_str = ctypes.c_wchar_p()
                    hr = _vtbl_call(p_item, 5, ctypes.HRESULT,
                                    [ctypes.c_void_p, wintypes.DWORD,
                                     ctypes.POINTER(ctypes.c_wchar_p)],
                                    wintypes.DWORD(SIGDN_FILESYSPATH),
                                    ctypes.byref(p_str))
                    # On success GetDisplayName ALLOCATES a co-task-mem string and hands
                    # back a non-NULL pointer; the CALLER owns it and MUST CoTaskMemFree
                    # it (#26). Free on `hr == 0 and pointer non-NULL` REGARDLESS of the
                    # string CONTENT — the old `hr == 0 and p_str.value` skipped the free
                    # for a zero-length-but-allocated string, leaking it. Only APPEND a
                    # non-empty path, but free the buffer either way.
                    if hr == 0 and p_str.value is not None:
                        if p_str.value:
                            out.append(p_str.value)
                        ole32.CoTaskMemFree(ctypes.cast(p_str, ctypes.c_void_p))
                finally:
                    _vtbl_call(p_item, IDX_RELEASE, ctypes.c_ulong,
                               [ctypes.c_void_p])
            paths = out
        finally:
            _vtbl_call(p_results, IDX_RELEASE, ctypes.c_ulong, [ctypes.c_void_p])
        return paths
    finally:
        if p_dialog:
            try:
                _vtbl_call(p_dialog, 2, ctypes.c_ulong, [ctypes.c_void_p])
            except Exception:
                pass
        if com_initialized_here:
            try:
                ole32.CoUninitialize()
            except Exception:
                pass
