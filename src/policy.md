---
policy-version: 2
---

```policy
use afc
// use crypto
use device
// use envelope
// use idam
use perspective
use c2

struct Envelope {
    parent_id id,
    author_id id,
    command_id id,
    payload bytes,
    signature bytes
}

function do_seal(payload bytes) struct Envelope {
    let parent_id = perspective::head_id()
    let device_id = device::current_device_id()

    return Envelope {
        parent_id: c2::nullid(),
        author_id: device_id,
        command_id: c2::randomid(),
        payload: payload,
        signature: payload,
    }
}

command Init {
    attributes {
        init: true
    }

    seal {
        let parent_id = perspective::head_id()
        let device_id = device::current_device_id()
        let payload = serialize(this)

        return Envelope {
            parent_id: parent_id,
            author_id: device_id,
            command_id: c2::nullid(),
            payload: payload,
            signature: payload,
        }
    }

    open {
        return deserialize(envelope.payload)
    }

    policy {
        finish { }
    }
}

action init() {
    publish Init { }
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
        return deserialize(envelope.payload)
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

effect CommandResult {
    cmd id,
    result string
}

command CommandExecuted {
    attributes {
        priority: 200
    }

    fields {
        cmd id,
        result string
    }

    seal {
        return do_seal(serialize(this))
    }

    open {
        return deserialize(envelope.payload)
    }

    policy {
        let device = query Device[device_id: envelope.author_id]

        if !(device is None) {
            let dev = unwrap device
            finish {
                update Device[device_id: envelope.author_id] => {
                    last_heartbeat: dev.last_heartbeat,
                    last_command: dev.last_command,
                    last_output: dev.last_output
                } to {
                    last_heartbeat: dev.last_heartbeat,
                    last_command: this.cmd,
                    last_output: this.result
                }
            }
        }

        finish {
            emit CommandResult {
                cmd: this.cmd,
                result: this.result
            }
        }
    }
}

action command_executed(cmd id, result string) {
    publish CommandExecuted {
        cmd: cmd,
        result: result
    }
}

fact Device[device_id id] => {
    last_heartbeat int,
    last_command id,
    last_output string
}

command HeartbeatCommand {
    attributes {
        priority: 200
    }

    fields {
        timestamp int
    }

    seal {
        return do_seal(serialize(this))
    }

    open {
        return deserialize(envelope.payload)
    }

    policy {
        let device = query Device[device_id: envelope.author_id]
        let nullid = c2::nullid()
        if device is None {
            finish {
                create Device[device_id: envelope.author_id] => {
                    last_heartbeat: this.timestamp,
                    last_command: nullid,
                    last_output: ""
                }
            }
        } else {
            let devunwrap = unwrap device
            finish {
                update Device[device_id: envelope.author_id] => {
                    last_heartbeat: devunwrap.last_heartbeat,
                    last_command: devunwrap.last_command,
                    last_output: devunwrap.last_output
                } to {
                    last_heartbeat: this.timestamp,
                    last_command: devunwrap.last_command,
                    last_output: devunwrap.last_output
                }
            }
        }
    }
}

action heartbeat() {
    publish HeartbeatCommand {
        timestamp: c2::current_timestamp()
    }
}

effect QueryDevicesResult {
    device_id id,
    last_heartbeat int,
    last_command id,
    last_output string
}

ephemeral command QueryDevicesCommand {
    fields {
        device_id id,
        last_heartbeat int,
        last_command id,
        last_output string
    }

    seal {
        return do_seal(serialize(this))
    }

    open {
        return deserialize(envelope.payload)
    }

    policy {
        finish {
            emit QueryDevicesResult {
                device_id: this.device_id,
                last_heartbeat: this.last_heartbeat,
                last_command: this.last_command,
                last_output: this.last_output
            }
        }
    }
}

ephemeral action query_devices() {
    map Device[device_id: ?] as device {
        publish QueryDevicesCommand {
            device_id: device.device_id,
            last_heartbeat: device.last_heartbeat,
            last_command: device.last_command,
            last_output: device.last_output
        }
    }
}
```
