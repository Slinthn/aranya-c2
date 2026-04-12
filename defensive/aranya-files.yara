rule AranyaFiles {
    meta:
        description = "Detects files relating to the Aranya Framework"
        author = "Alex Ringhoffer"
    
    strings:
        // Header is present in Aranya graph files
        $header = { A4 62 69 64 58 20 }

        $s1 = "nonce"
        $s2 = "ciphertext"
        $s3 = "Deca"
        $s4 = "Signing"
        $s5 = "tag"

    condition:
        // Filenames typically have 44 characters
        // filename matches /^[a-z0-9]{44}/i or
        // An aranya store has a file called this
        // filename matches "__canary" or
        $header or
        3 of ($s*)
}
