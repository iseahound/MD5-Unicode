MD5(s) {
   size := StrPut(s, "UTF-8") - 1 ; bin has no null
   bin := Buffer(size)
   StrPut(s, bin, "UTF-8")

   MD5_CTX := Buffer(104)
   DllCall("advapi32\MD5Init", "ptr", MD5_CTX)
   DllCall("advapi32\MD5Update", "ptr", MD5_CTX, "ptr", bin, "uint", size)
   DllCall("advapi32\MD5Final", "ptr", MD5_CTX)

   VarSetStrCapacity(&md5, 32 + 1) ; str has null
   DllCall("crypt32\CryptBinaryToString", "ptr", MD5_CTX.ptr+88, "uint", 16, "uint", 0x4000000c, "str", md5, "uint*", 33)
   return md5
}
