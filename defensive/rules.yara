rule AranyaFile {
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
        $header at 0 and
        3 of ($s*)
}

rule AranyaExecutable {
    meta:
        description = "Detects executables using Aranya"
        author = "Alex Ringhoffer"

    strings:
        $s1 = "aranya_policy_vm"
        $s2 = "aranya_crypto"
        $s3 = "aranya_runtime"

    condition:
        all of ($s*)
}

// This is suspicious because Aranya supports AFC. However, when making
//   C2 malware using Aranya, it is not possible to use AFC.
rule AranyaSuspiciousCrypto {
    meta:
        description = "Detects if Aranya is being used alongside other forms of cryptography (RSA)"
        author = "Alex Ringhoffer"

    strings:
        $s1 = "aranya_policy_vm"
        $s2 = "aranya_crypto"
        $s3 = "aranya_runtime"
        $s4 = "RsaPublicKey"

        $n1 = "aranya_afc"

    condition:
        all of ($s*) and not any of ($n*)
}

rule AranyaSuspiciousPolicy {
    meta:
        description = "Detects suspicious Aranya uncompiled policy keywords embedded in binary"
        author = "Alex Ringhoffer"

    strings:
        $i1 = "policy-version: "
        $i2 = "policy-version: "

        $s1 = "cmdline"
        $s2 = "c2"

    condition:
        all of ($i*) and all of ($s*)
}

rule SuspiciousDGA {
    meta:
        description = "Detects a possible DGA algorithm"
        author = "Alex Ringhoffer"

    strings:
        // MOVUPS xmm2/m128, xmm1
        $b1 = { 0F 11 ?? ?? ?? ?? ?? ?? }

        $l1 = "0123456789"
        $l2 = "abcdefghijklmnopqrstuvwxyz"

        // Datetime util
        $s1 = "chrono..format"

    condition:
        $b1 and
        #b1 >= 32 and
        all of ($l*) and
        all of ($s*)
}
