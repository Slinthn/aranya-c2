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

// struct Envelope {
//     parent_id id,
//     author_id id,
//     command_id id,
//     payload bytes,
//     signature bytes
// }

fact DeviceSignPk[device_id id] => {
    key bytes    
}

fact DeviceIdentPk[device_id id] => {
    key bytes    
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

        // return do_seal(serialize(this))
        // let parent_id = perspective::head_id()
        // let device_id = device::current_device_id()
        // let payload = serialize(this)

        // return Envelope {
        //     parent_id: parent_id,
        //     author_id: device_id,
        //     command_id: c2::nullid(),
        //     payload: payload,
        //     signature: payload,
        // }
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
        }
    }
}

action init(keys struct PublicKeyBundle) {
    publish Init {
        keys: keys
    }
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
        finish {
            emit Command { cmdline: this.cmdline }
        }
    }
}

action execute_command(cmdline string) {
    publish CommandExecution {
        cmdline: cmdline
    }
}

// effect CommandResult {
//     cmd id,
//     result string
// }

// command CommandExecuted {
//     attributes {
//         priority: 200
//     }

//     fields {
//         cmd id,
//         result string
//     }

//     seal {
//         return do_seal(serialize(this))
//     }

//     open {
//         return deserialize(do_open(envelope))
//     }

//     policy {
//         let device = query Device[device_id: envelope.author_id]

//         if !(device is None) {
//             let dev = unwrap device
//             finish {
//                 update Device[device_id: envelope.author_id] => {
//                     last_heartbeat: dev.last_heartbeat,
//                     last_command: dev.last_command,
//                     last_output: dev.last_output
//                 } to {
//                     last_heartbeat: dev.last_heartbeat,
//                     last_command: this.cmd,
//                     last_output: this.result
//                 }
//             }
//         }

//         finish {
//             emit CommandResult {
//                 cmd: this.cmd,
//                 result: this.result
//             }
//         }
//     }
// }

// action command_executed(cmd id, result string) {
//     publish CommandExecuted {
//         cmd: cmd,
//         result: result
//     }
// }

// fact Device[device_id id] => {
//     last_heartbeat int,
//     last_command id,
//     last_output string
// }

// command HeartbeatCommand {
//     attributes {
//         priority: 300
//     }

//     fields {
//         timestamp int,
//         keys struct PublicKeyBundle
//     }

//     seal {
//         let payload = serialize(this)
//         let parent_id = perspective::head_id()
//         let device_id = device::current_device_id()
//         // let pk = check_unwrap query DeviceSignPk[device_id: device_id]
//         let sig = crypto::sign(
//             idam::derive_sign_key_id(this.keys.sign_key),
//             payload
//         )

//         return envelope::new(
//             parent_id,
//             device_id,
//             sig.command_id,
//             sig.signature,
//             payload,
//         )
//     }

//     open {
//         let payload = envelope::payload(envelope)
//         let pk = deserialize(payload).keys.sign_key

//         let author_id = envelope::author_id(envelope)
//         // let pk = check_unwrap query DeviceSignPk[device_id: author_id]

//         return deserialize(crypto::verify(
//             pk,
//             envelope::parent_id(envelope),
//             payload,
//             envelope::command_id(envelope),
//             envelope::signature(envelope),
//         ))



//         // let verified = crypto::verify(
//         //     pk,
//         //     envelope::parent_id(envelope),
//         //     payload,
//         //     envelope::command_id(envelope),
//         //     envelope::signature(envelope)
//         // )

//         // return deserialize(verified)
//     }

//     policy {
//         // let author_id = envelope::author_id(envelope)
//         // let device_id = envelope::author_id(envelope)
//         let device_id = idam::derive_device_id(this.keys.ident_key)

//         let keys = query DeviceSignPk[device_id: device_id]

//         if keys is None {
//             finish {
//                 create DeviceSignPk[device_id: device_id] => {
//                     key: this.keys.sign_key
//                 }

//                 create DeviceIdentPk[device_id: device_id] => {
//                     key: this.keys.ident_key
//                 }
//             }
//         }

//         let device = query Device[device_id: device_id]
//         let nullid = c2::nullid()
//         if device is None {
//             finish {
//                 create Device[device_id: device_id] => {
//                     last_heartbeat: this.timestamp,
//                     last_command: nullid,
//                     last_output: ""
//                 }
//             }
//         } else {
//             let devunwrap = unwrap device
//             finish {
//                 update Device[device_id: device_id] => {
//                     last_heartbeat: devunwrap.last_heartbeat,
//                     last_command: devunwrap.last_command,
//                     last_output: devunwrap.last_output
//                 } to {
//                     last_heartbeat: this.timestamp,
//                     last_command: devunwrap.last_command,
//                     last_output: devunwrap.last_output
//                 }
//             }
//         }
//     }
// }

// action heartbeat(keys struct PublicKeyBundle) {
//     publish HeartbeatCommand {
//         timestamp: c2::current_timestamp(),
//         keys: keys
//     }
// }

// effect QueryDevicesResult {
//     device_id id,
//     last_heartbeat int,
//     last_command id,
//     last_output string
// }

// ephemeral command QueryDevicesCommand {
//     fields {
//         device_id id,
//         last_heartbeat int,
//         last_command id,
//         last_output string
//     }

//     seal {
//         return do_seal(serialize(this))
//     }

//     open {
//         return deserialize(do_open(envelope))
//     }

//     policy {
//         finish {
//             emit QueryDevicesResult {
//                 device_id: this.device_id,
//                 last_heartbeat: this.last_heartbeat,
//                 last_command: this.last_command,
//                 last_output: this.last_output
//             }
//         }
//     }
// }

// ephemeral action query_devices() {
//     map Device[device_id: ?] as device {
//         publish QueryDevicesCommand {
//             device_id: device.device_id,
//             last_heartbeat: device.last_heartbeat,
//             last_command: device.last_command,
//             last_output: device.last_output
//         }
//     }
// }
```
