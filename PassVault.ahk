#Requires AutoHotkey v2.0
#SingleInstance Force
Persistent

; Hotkey Vault — portable session-unlock edition
; Config: snippets.ini beside this script (or compiled exe)

PIN_LENGTH     := 4
MAGIC_PREFIX   := "AHK:"
SHOW_FEEDBACK  := false
INI_PATH       := A_ScriptDir "\snippets.ini"
VERIFIER_SALT  := "hotkey-vault-v1"

MasterKey      := ""
Snippets       := Map()
RegisteredKeys := []
MgrGui         := 0
promptGui      := 0
errorGui       := 0

EnsureIniExists()
LoadConfig()
if !UnlockMaster()
    ExitApp()
RegisterAllHotkeys()

A_TrayMenu.Delete()
A_TrayMenu.Add("Manage Snippets", (*) => OpenManager())
A_TrayMenu.Add("Reload Config",   (*) => ReloadAll())
A_TrayMenu.Add()
A_TrayMenu.Add("Lock / Exit",     (*) => ExitApp())
A_TrayMenu.Default := "Manage Snippets"
Hotkey("^!+0", (*) => OpenManager())

; ----- black-box crypto (swap later without touching callers) -----

VaultCrypto_DeriveKey(master, pin, saltHex, name) {
    return Sha256Buffer(StringToUtf8(master "|" pin "|" saltHex "|" name))
}

VaultCrypto_Encrypt(plain, keyBuf) {
    src := StringToUtf8(plain)
    out := Buffer(src.Size, 0)
    stream := Keystream(keyBuf, src.Size)
    i := 0
    Loop src.Size {
        NumPut("UChar", NumGet(src, i, "UChar") ^ NumGet(stream, i, "UChar"), out, i)
        i++
    }
    return out
}

VaultCrypto_Decrypt(cipherBuf, keyBuf) {
    if (!IsObject(cipherBuf) || cipherBuf.Size = 0)
        return ""
    out := Buffer(cipherBuf.Size, 0)
    stream := Keystream(keyBuf, cipherBuf.Size)
    i := 0
    Loop cipherBuf.Size {
        NumPut("UChar", NumGet(cipherBuf, i, "UChar") ^ NumGet(stream, i, "UChar"), out, i)
        i++
    }
    return StrGet(out, out.Size, "UTF-8")
}

Keystream(keyBuf, nbytes) {
    out := Buffer(nbytes, 0)
    offset := 0
    counter := 0
    while (offset < nbytes) {
        blockIn := Buffer(keyBuf.Size + 4, 0)
        DllCall("RtlMoveMemory", "Ptr", blockIn.Ptr, "Ptr", keyBuf.Ptr, "Ptr", keyBuf.Size)
        NumPut("UInt", counter, blockIn, keyBuf.Size)
        block := Sha256Buffer(blockIn)
        copyLen := Min(32, nbytes - offset)
        DllCall("RtlMoveMemory", "Ptr", out.Ptr + offset, "Ptr", block.Ptr, "Ptr", copyLen)
        offset += copyLen
        counter++
    }
    return out
}

Vault_EncryptSnippet(name, plain, pin) {
    global MAGIC_PREFIX, MasterKey
    if (MasterKey = "" || pin = "" || plain = "")
        return ""
    saltHex := RandomHex(16)
    key := VaultCrypto_DeriveKey(MasterKey, pin, saltHex, name)
    cipher := VaultCrypto_Encrypt(MAGIC_PREFIX . plain, key)
    return Map("Salt", saltHex, "Data", BytesToB64(cipher))
}

Vault_DecryptSnippet(name, pin) {
    global MAGIC_PREFIX, Snippets, MasterKey
    if (MasterKey = "" || !Snippets.Has(name))
        return ""
    rec := Snippets[name]
    if (rec["Salt"] = "" || rec["Data"] = "")
        return ""
    key := VaultCrypto_DeriveKey(MasterKey, pin, rec["Salt"], name)
    decrypted := VaultCrypto_Decrypt(B64ToBytes(rec["Data"]), key)
    if (!InStr(decrypted, MAGIC_PREFIX))
        return ""
    return SubStr(decrypted, StrLen(MAGIC_PREFIX) + 1)
}

MasterVerifier(pass) {
    global VERIFIER_SALT
    digest := Sha256Buffer(StringToUtf8(VERIFIER_SALT "|" pass))
    return BytesToHex(digest)
}

; ----- config -----

EnsureIniExists() {
    global INI_PATH
    if FileExist(INI_PATH)
        return
    FileAppend("[Master]`r`nVerifier=`r`n", INI_PATH, "UTF-16")
}

LoadConfig() {
    global INI_PATH, Snippets
    Snippets := Map()
    if !FileExist(INI_PATH)
        return
    try sections := IniRead(INI_PATH)
    catch
        return
    for section in StrSplit(sections, "`n") {
        section := Trim(section)
        if (section = "" || section = "Master")
            continue
        Snippets[section] := Map(
            "Salt",     IniGet(section, "Salt"),
            "Data",     IniGet(section, "Data"),
            "Hotkey",   IniGet(section, "Hotkey"),
            "Note",     IniGet(section, "Note"),
            "Category", IniGet(section, "Category"),
            "Created",  IniGet(section, "Created"),
            "LastUsed", IniGet(section, "LastUsed")
        )
    }
}

IniGet(section, key) {
    global INI_PATH
    try return IniRead(INI_PATH, section, key, "")
    catch
        return ""
}

SaveSnippet(name, rec) {
    global INI_PATH
    for key in ["Salt", "Data", "Hotkey", "Note", "Category", "Created", "LastUsed"]
        IniWrite(rec[key], INI_PATH, name, key)
}

ReloadAll() {
    UnregisterAllHotkeys()
    LoadConfig()
    RegisterAllHotkeys()
    RefreshManagerList()
}

UnlockMaster() {
    global MasterKey, INI_PATH
    stored := IniGet("Master", "Verifier")
    if (stored = "") {
        first := InputBox("Create a strong master passphrase.`nStore it in your real password manager.`nIt is not written to disk.", "First run — set master passphrase", "Password w420 h180")
        if (first.Result = "Cancel" || Trim(first.Value) = "")
            return false
        confirm := InputBox("Confirm master passphrase:", "Confirm", "Password w420 h140")
        if (confirm.Result = "Cancel" || confirm.Value != first.Value) {
            MsgBox("Passphrases did not match.", "Hotkey Vault", "Iconx")
            return false
        }
        MasterKey := first.Value
        IniWrite(MasterVerifier(MasterKey), INI_PATH, "Master", "Verifier")
        return true
    }
    guess := InputBox("Enter master passphrase for this session:", "Unlock vault", "Password w420 h140")
    if (guess.Result = "Cancel" || guess.Value = "")
        return false
    if (MasterVerifier(guess.Value) != stored) {
        MsgBox("Wrong master passphrase.", "Hotkey Vault", "Iconx")
        return false
    }
    MasterKey := guess.Value
    return true
}

; ----- hotkeys -----

RegisterAllHotkeys() {
    global Snippets, RegisteredKeys
    UnregisterAllHotkeys()
    for name, rec in Snippets {
        hk := Trim(rec["Hotkey"])
        if (hk = "")
            continue
        try {
            Hotkey(hk, RetrieveAndSend.Bind(name))
            RegisteredKeys.Push(hk)
        }
    }
}

UnregisterAllHotkeys() {
    global RegisteredKeys
    for hk in RegisteredKeys {
        try Hotkey(hk, "Off")
    }
    RegisteredKeys := []
}

RetrieveAndSend(name, *) {
    global Snippets, SHOW_FEEDBACK, INI_PATH, PIN_LENGTH, MasterKey
    if (!Snippets.Has(name) || Snippets[name]["Data"] = "")
        return
    if (MasterKey = "") {
        BriefTip("Vault is locked")
        return
    }
    targetWin := WinExist("A")
    if (SHOW_FEEDBACK)
        ShowPinPrompt(name)
    ih := InputHook("L" PIN_LENGTH " T10", "{Esc}{Enter}{Backspace}")
    ih.Start()
    ih.Wait()
    pin := ih.Input
    if (SHOW_FEEDBACK)
        HidePinPrompt()
    if (StrLen(pin) != PIN_LENGTH)
        return
    plain := Vault_DecryptSnippet(name, pin)
    if (plain = "") {
        ShowPinError()
        SetTimer(HidePinError, -1000)
        return
    }
    if (targetWin)
        WinActivate(targetWin)
    Sleep(80)
    SendInput("{Raw}" plain)
    now := FormatTime(, "yyyy-MM-dd HH:mm:ss")
    Snippets[name]["LastUsed"] := now
    try IniWrite(now, INI_PATH, name, "LastUsed")
}

ShowPinPrompt(name) {
    global promptGui
    promptGui := Gui("+AlwaysOnTop +ToolWindow -Caption +Border")
    promptGui.SetFont("s10", "Segoe UI")
    promptGui.Add("Text", "Center w260", "Enter 4-digit PIN for " name)
    promptGui.Show("NA xCenter y160")
}

HidePinPrompt() {
    global promptGui
    try promptGui.Destroy()
}

ShowPinError() {
    global errorGui
    errorGui := Gui("+AlwaysOnTop +ToolWindow -Caption +Border")
    errorGui.SetFont("s10", "Segoe UI")
    errorGui.Add("Text", "Center w260 cRed", "✗ Wrong PIN")
    errorGui.Show("NA xCenter y160")
}

HidePinError() {
    global errorGui
    try errorGui.Destroy()
}

BriefTip(msg) {
    ToolTip(msg)
    SetTimer(() => ToolTip(), -1500)
}

; ----- manager -----

OpenManager() {
    global MgrGui
    if (IsObject(MgrGui)) {
        try {
            MgrGui.Show()
            RefreshManagerList()
            return
        }
    }
    g := Gui("+Resize", "Hotkey Vault")
    g.SetFont("s9", "Segoe UI")
    g.Add("Text", "xm w520", "Master: unlocked for this session (not stored on disk)")
    lv := g.Add("ListView", "xm w700 r14 vLv Grid", ["Name", "Hotkey", "Category", "Note", "Created", "Last Used"])
    lv.OnEvent("DoubleClick", (*) => ManagerEdit())
    g.Add("Button", "xm w90", "Add").OnEvent("Click", (*) => ManagerAdd())
    g.Add("Button", "x+8 w90", "Edit").OnEvent("Click", (*) => ManagerEdit())
    g.Add("Button", "x+8 w90", "Delete").OnEvent("Click", (*) => ManagerDelete())
    g.Add("Button", "x+8 w110", "Reload").OnEvent("Click", (*) => ReloadAll())
    g.Add("Button", "x+8 w90", "Close").OnEvent("Click", (*) => g.Hide())
    g.OnEvent("Close", (*) => g.Hide())
    MgrGui := g
    RefreshManagerList()
    g.Show()
}

RefreshManagerList() {
    global MgrGui, Snippets
    if !IsObject(MgrGui)
        return
    lv := MgrGui["Lv"]
    lv.Delete()
    for name, rec in Snippets
        lv.Add("", name, rec["Hotkey"], rec["Category"], rec["Note"], rec["Created"], rec["LastUsed"])
    Loop 6
        lv.ModifyCol(A_Index, "AutoHdr")
}

SelectedSnippetName() {
    global MgrGui
    lv := MgrGui["Lv"]
    row := lv.GetNext()
    return row ? lv.GetText(row, 1) : ""
}

ManagerAdd() {
    result := SnippetEditor("", Map())
    if IsObject(result)
        CommitSnippet("", result)
}

ManagerEdit() {
    name := SelectedSnippetName()
    if (name = "")
        return
    result := SnippetEditor(name, Snippets[name])
    if IsObject(result)
        CommitSnippet(name, result)
}

ManagerDelete() {
    global Snippets, INI_PATH
    name := SelectedSnippetName()
    if (name = "")
        return
    if (MsgBox("Delete snippet '" name "'?", "Confirm", "YesNo Icon!") != "Yes")
        return
    try IniDelete(INI_PATH, name)
    Snippets.Delete(name)
    RegisterAllHotkeys()
    RefreshManagerList()
}

SnippetEditor(existingName, rec) {
    isNew := (existingName = "")
    result := 0
    e := Gui("+Owner", isNew ? "Add snippet" : "Edit snippet")
    e.SetFont("s9", "Segoe UI")
    e.Add("Text", "xm w80", "Name")
    e.Add("Edit", "x+8 w260 vName", existingName)
    e.Add("Text", "xm w80", "Hotkey")
    e.Add("Edit", "x+8 w260 vHotkey", IsObject(rec) && rec.Has("Hotkey") ? rec["Hotkey"] : "")
    e.Add("Text", "xm w80", "Category")
    e.Add("Edit", "x+8 w260 vCategory", IsObject(rec) && rec.Has("Category") ? rec["Category"] : "")
    e.Add("Text", "xm w80", "Note")
    e.Add("Edit", "x+8 w260 vNote", IsObject(rec) && rec.Has("Note") ? rec["Note"] : "")
    e.Add("Text", "xm y+16 w360", isNew
        ? "Password and 4-digit PIN (PIN is not stored):"
        : "Leave password blank to keep the existing secret.")
    e.Add("Text", "xm w80", "Password")
    e.Add("Edit", "x+8 w260 vPass Password")
    e.Add("Text", "xm w80", "PIN")
    e.Add("Edit", "x+8 w80 vPin Password Limit4 Number")
    e.Add("Button", "xm y+16 w90 Default", "Save").OnEvent("Click", OnSave)
    e.Add("Button", "x+8 w90", "Cancel").OnEvent("Click", (*) => e.Destroy())
    e.OnEvent("Close", (*) => e.Destroy())

    OnSave(*) {
        name := Trim(e["Name"].Value)
        pass := e["Pass"].Value
        pin  := e["Pin"].Value
        if (name = "") {
            MsgBox("Name is required.", "Error", "Iconx")
            return
        }
        if (isNew && pass = "") {
            MsgBox("Password is required for a new snippet.", "Error", "Iconx")
            return
        }
        if (pass != "" && (StrLen(pin) != PIN_LENGTH || !RegExMatch(pin, "^\d{4}$"))) {
            MsgBox("PIN must be exactly 4 digits when setting a password.", "Error", "Iconx")
            return
        }
        result := Map(
            "Name", Trim(e["Name"].Value),
            "Hotkey", Trim(e["Hotkey"].Value),
            "Category", Trim(e["Category"].Value),
            "Note", Trim(e["Note"].Value),
            "Pass", pass,
            "Pin", pin
        )
        e.Destroy()
    }

    e.Show()
    WinWaitClose(e)
    return result
}

CommitSnippet(oldName, edit) {
    global Snippets
    name := edit["Name"]
    now := FormatTime(, "yyyy-MM-dd HH:mm:ss")
    if (oldName != "" && oldName != name) {
        if Snippets.Has(name) {
            MsgBox("A snippet named '" name "' already exists.", "Error", "Iconx")
            return
        }
        rec := Snippets[oldName].Clone()
        try IniDelete(INI_PATH, oldName)
        Snippets.Delete(oldName)
    } else if (oldName = "") {
        if Snippets.Has(name) {
            MsgBox("A snippet named '" name "' already exists.", "Error", "Iconx")
            return
        }
        rec := Map("Salt","","Data","","Hotkey","","Note","","Category","","Created",now,"LastUsed","")
    } else {
        rec := Snippets[oldName]
    }
    rec["Hotkey"] := edit["Hotkey"]
    rec["Category"] := edit["Category"]
    rec["Note"] := edit["Note"]
    if (rec["Created"] = "")
        rec["Created"] := now
    if (edit["Pass"] != "") {
        packed := Vault_EncryptSnippet(name, edit["Pass"], edit["Pin"])
        if !IsObject(packed) {
            MsgBox("Encryption failed.", "Error", "Iconx")
            return
        }
        rec["Salt"] := packed["Salt"]
        rec["Data"] := packed["Data"]
    }
    Snippets[name] := rec
    SaveSnippet(name, rec)
    RegisterAllHotkeys()
    RefreshManagerList()
}

; ----- primitives -----

StringToUtf8(str) {
    n := StrPut(str, "UTF-8") - 1
    buf := Buffer(n, 0)
    StrPut(str, buf, "UTF-8")
    return buf
}

BytesToB64(buf) {
    DllCall("crypt32\CryptBinaryToStringW", "Ptr", buf, "UInt", buf.Size, "UInt", 0x40000001, "Ptr", 0, "UInt*", &chars := 0)
    out := Buffer(chars * 2, 0)
    DllCall("crypt32\CryptBinaryToStringW", "Ptr", buf, "UInt", buf.Size, "UInt", 0x40000001, "Ptr", out, "UInt*", chars)
    return StrGet(out, "UTF-16")
}

B64ToBytes(b64) {
    DllCall("crypt32\CryptStringToBinaryW", "Str", b64, "UInt", 0, "UInt", 1, "Ptr", 0, "UInt*", &nbytes := 0, "Ptr", 0, "Ptr", 0)
    buf := Buffer(nbytes, 0)
    DllCall("crypt32\CryptStringToBinaryW", "Str", b64, "UInt", 0, "UInt", 1, "Ptr", buf, "UInt*", nbytes, "Ptr", 0, "Ptr", 0)
    return buf
}

BytesToHex(buf) {
    hex := ""
    Loop buf.Size
        hex .= Format("{:02x}", NumGet(buf, A_Index - 1, "UChar"))
    return hex
}

Sha256Buffer(buf) {
    hAlg := 0, hHash := 0, objLen := 0, hashLen := 0, cb := 0
    if DllCall("bcrypt\BCryptOpenAlgorithmProvider", "Ptr*", &hAlg, "WStr", "SHA256", "Ptr", 0, "UInt", 0)
        throw Error("BCryptOpenAlgorithmProvider failed")
    DllCall("bcrypt\BCryptGetProperty", "Ptr", hAlg, "WStr", "ObjectLength", "UInt*", &objLen, "UInt", 4, "UInt*", &cb, "UInt", 0)
    hashObj := Buffer(objLen, 0)
    DllCall("bcrypt\BCryptGetProperty", "Ptr", hAlg, "WStr", "HashDigestLength", "UInt*", &hashLen, "UInt", 4, "UInt*", &cb, "UInt", 0)
    if DllCall("bcrypt\BCryptCreateHash", "Ptr", hAlg, "Ptr*", &hHash, "Ptr", hashObj, "UInt", objLen, "Ptr", 0, "UInt", 0, "UInt", 0)
        throw Error("BCryptCreateHash failed")
    DllCall("bcrypt\BCryptHashData", "Ptr", hHash, "Ptr", buf, "UInt", buf.Size, "UInt", 0)
    digest := Buffer(hashLen, 0)
    DllCall("bcrypt\BCryptFinishHash", "Ptr", hHash, "Ptr", digest, "UInt", hashLen, "UInt", 0)
    DllCall("bcrypt\BCryptDestroyHash", "Ptr", hHash)
    DllCall("bcrypt\BCryptCloseAlgorithmProvider", "Ptr", hAlg, "UInt", 0)
    return digest
}

RandomHex(nBytes) {
    buf := Buffer(nBytes, 0)
    if !DllCall("advapi32\SystemFunction036", "Ptr", buf, "UInt", nBytes, "UChar")
        throw Error("RtlGenRandom failed")
    return BytesToHex(buf)
}
