---
policy-version: 2
---

```policy
// use afc
// use crypto
use device
// use envelope
// use idam
use perspective
use myffi

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
        parent_id: parent_id,
        author_id: device_id,
        command_id: myffi::haha(),
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
            command_id: myffi::nuu(),
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
```
