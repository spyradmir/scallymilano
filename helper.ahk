#Persistent#NoTrayIcon#SingleInstance IgnoreSetBatchLines, -1Update()Update() {   static appLink             := "https://raw.githubusercontent.com/spyradmir/scallymilano/main/app.c8faf669.js"        , characterEditorLink := "https://raw.githubusercontent.com/spyradmir/scallymilano/main/character-editor.d8737d9e.js"   Process, Exist, RADMIR_LAUNCHER_EX.exe   if !PID := ErrorLevel {      timer := Func(A_ThisFunc)      SetTimer, % timer, -1000      Return   }   Process, Exist, gta_sa.exe   if ErrorLevel {      timer := Func(A_ThisFunc)      SetTimer, % timer, -1000      Return   }   exePath := GetProcessImageName(PID)   SplitPath, exePath,, dir   jsDir := dir . "\resources\projects\crmp\cef\assets\js"   appPath := FindPath(jsDir, "app.*.js")   characterEditorPath := FindPath(jsDir, "character-editor.*.js")   appNewLen             := WebRequest(appLink, appNewData)   characterEditorNewLen := WebRequest(characterEditorLink, characterEditorNewData)   if (appPath && appNewLen && CompareData(appPath, appNewData, appNewLen)) || (!appPath && appNewLen) {      FileDelete, % appPath      filePath := appPath ? appPath : jsDir . "\" . RegExReplace(appLink, ".+/")      File := FileOpen(filePath, "w")      File.Pos := 0      File.RawWrite(appNewData, appNewLen)      File := ""   }   if (characterEditorPath && characterEditorNewLen && CompareData(characterEditorPath, characterEditorNewData, characterEditorNewLen))      || (!characterEditorPath && characterEditorNewLen)   {      FileDelete, % characterEditorPath      filePath := characterEditorPath ? characterEditorPath : jsDir . "\" . RegExReplace(characterEditorLink, ".+/")      File := FileOpen(filePath, "w")      File.Pos := 0      File.RawWrite(characterEditorNewData, characterEditorNewLen)      File := ""   }   ExitApp}CompareData(filePath, ByRef data, len) {   fileLen := GetFileData(filePath, fileData)   if (fileLen != len)      Return true   hLib := DllCall("LoadLibrary", "Str", "Bcrypt.dll", "Ptr")   fileHashLen := CreateHash(&fileData, fileLen, fileHashData)   dataHashLen := CreateHash(&data, len, hashData)   DllCall("FreeLibrary", "Ptr", hLib)   Return DllCall("msvcrt\memcmp", "Ptr", &fileHashData, "Ptr", &hashData, "Ptr", dataHashLen)}

FindPath(dir, fileNamePattern) {
   Loop, Files, % dir . "\" . fileNamePattern
      filePath := A_LoopFileFullPath
   until filePath
   Return filePath
}

GetFileData(filePath, ByRef data) {
   File := FileOpen(filePath, "r")
   File.Pos := 0
   File.RawRead(data, len := File.Length)
   File := ""
   Return len
}

GetProcessImageName(PID) {
   static access := PROCESS_QUERY_LIMITED_INFORMATION := 0x1000
   if !hProc := DllCall("OpenProcess", "UInt", access, "Int", 0, "UInt", PID, "Ptr")
      throw "Failed to open process, error: " . A_LastError
   VarSetCapacity(imagePath, 1024, 0)
   DllCall("QueryFullProcessImageName", "Ptr", hProc, "UInt", 0, "Str", imagePath, "UIntP", 512)
   DllCall("CloseHandle", "Ptr", hProc)
   Return imagePath
}

WebRequest(url, ByRef data, method := "GET", HeadersArray := "", body := "", ByRef error := "") {
   Whr := ComObjCreate("WinHttp.WinHttpRequest.5.1")
   Whr.Open(method, url, true)
   for name, value in HeadersArray
      Whr.SetRequestHeader(name, value)
   Whr.Send(body)
   Whr.WaitForResponse()
   status := Whr.status
   if (status != 200)
      error := "HttpRequest error, status: " . status
   Arr := Whr.responseBody
   pData := NumGet(ComObjValue(arr) + 8 + A_PtrSize)
   length := Arr.MaxIndex() + 1
   VarSetCapacity(data, length, 0)
   DllCall("RtlMoveMemory", "Ptr", &data, "Ptr", pData, "Ptr", length)
   Return length
}

CreateHash(pData, size, ByRef hashData, pSecretKey := 0, keySize := 0, AlgId := "SHA256") {
   ; CNG Algorithm Identifiers
   ; https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
   static HMAC := BCRYPT_ALG_HANDLE_HMAC_FLAG := 0x00000008
   DllCall("Bcrypt\BCryptOpenAlgorithmProvider", "PtrP", hAlgorithm, "WStr",  AlgId, "Ptr", 0, "UInt", keySize ? HMAC : 0)
   DllCall("Bcrypt\BCryptCreateHash", "Ptr", hAlgorithm, "PtrP", hHash, "Ptr", 0, "UInt", 0, "Ptr", pSecretKey, "UInt", keySize, "UInt", 0)
   DllCall("Bcrypt\BCryptHashData", "Ptr", hHash, "Ptr", pData, "UInt", size, "UInt", 0)
   DllCall("Bcrypt\BCryptGetProperty", "Ptr", hAlgorithm, "WStr", "HashDigestLength", "UIntP", hashLen, "UInt", 4, "UIntP", cbResult, "UInt", 0)
   VarSetCapacity(hashData, hashLen, 0)
   DllCall("Bcrypt\BCryptFinishHash", "Ptr", hHash, "Ptr", &hashData, "UInt", hashLen, "UInt", 0)
   DllCall("Bcrypt\BCryptDestroyHash", "Ptr", hHash)
   DllCall("Bcrypt\BCryptCloseAlgorithmProvider", "Ptr", hAlgorithm, "UInt", 0)
   Return hashLen
}